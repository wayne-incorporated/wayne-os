/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera_device_adapter.h"

#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/string_number_conversions.h>
#include <base/synchronization/lock.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <drm_fourcc.h>
#include <hardware/camera3.h>
#include <libyuv.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <sync/sync.h>
#include <system/camera_metadata.h>

#include "common/camera_buffer_handle.h"
#include "common/camera_hal3_helpers.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "cros-camera/future.h"
#include "cros-camera/tracing.h"
#include "cros-camera/utils/camera_config.h"
#include "hal_adapter/camera3_callback_ops_delegate.h"
#include "hal_adapter/camera3_device_ops_delegate.h"
#include "hal_adapter/camera_trace_event.h"

namespace cros {

std::ostream& operator<<(std::ostream& stream,
                         const CameraMonitor::MonitorType type) {
  switch (type) {
    case CameraMonitor::MonitorType::kRequestsMonitor:
      return stream << "requests";
    case CameraMonitor::MonitorType::kResultsMonitor:
      return stream << "results";
  }
}

constexpr base::TimeDelta kMonitorTimeDelta = base::Seconds(2);

CameraMonitor::CameraMonitor() : thread_("CameraMonitor") {
  CHECK(thread_.Start());
}

CameraMonitor::~CameraMonitor() {
  auto stop_all_monitors = [](CameraMonitor* self) {
    for (auto& [k, v] : self->monitor_states_) {
      self->StopMonitorOnThread(k);
      v.timer = nullptr;
    }
  };
  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(stop_all_monitors, base::Unretained(this)));
  thread_.Stop();
}

void CameraMonitor::StartMonitor(MonitorType type,
                                 base::OnceClosure timeout_callback) {
  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraMonitor::StartMonitorOnThread,
                                base::Unretained(this), type,
                                std::move(timeout_callback)));
}

void CameraMonitor::StopMonitor(MonitorType type) {
  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraMonitor::StopMonitorOnThread,
                                base::Unretained(this), type));
}

void CameraMonitor::Kick(MonitorType type) {
  thread_.task_runner()->PostTask(FROM_HERE,
                                  base::BindOnce(&CameraMonitor::KickOnThread,
                                                 base::Unretained(this), type));
}

bool CameraMonitor::HasBeenKicked(MonitorType type) {
  CHECK(thread_.IsRunning());
  auto future = cros::Future<bool>::Create(nullptr);
  auto check_if_kicked = [](CameraMonitor* self, MonitorType type,
                            base::OnceCallback<void(bool)> cb) {
    if (!self->monitor_states_.contains(type)) {
      std::move(cb).Run(false);
      return;
    }
    std::move(cb).Run(self->monitor_states_.at(type).is_kicked);
  };
  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(check_if_kicked, base::Unretained(this), type,
                                cros::GetFutureCallback(future)));
  future->Wait();
  return future->Get();
}

void CameraMonitor::StartMonitorOnThread(MonitorType type,
                                         base::OnceClosure timeout_callback) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  if (!monitor_states_.contains(type)) {
    monitor_states_.emplace(
        type,
        State{.timer = std::make_unique<base::RetainingOneShotTimer>(
                  FROM_HERE, kMonitorTimeDelta,
                  base::BindRepeating(&CameraMonitor::MonitorTimeoutOnThread,
                                      base::Unretained(this), type))});
  }

  State& s = monitor_states_.at(type);
  s.is_stopped = false;
  s.timeout_callback = std::move(timeout_callback);
  s.ResetTimer();
  LOGF(INFO) << "Started " << type << " monitor";
}

void CameraMonitor::StopMonitorOnThread(MonitorType type) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  if (!monitor_states_.contains(type) ||
      !monitor_states_.at(type).timer->IsRunning()) {
    return;
  }
  State& s = monitor_states_.at(type);
  s.timer->Stop();
  s.is_stopped = true;
  LOGF(INFO) << "Stopped " << type << " monitor";
}

void CameraMonitor::KickOnThread(MonitorType type) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  if (!monitor_states_.contains(type)) {
    LOGF(ERROR) << "CameraMonitor for " << type << " not started";
    return;
  }

  State& s = monitor_states_.at(type);
  s.is_kicked = true;
  if (s.is_stopped) {
    DVLOGF(1) << "CameraMonitor for " << type << " is kicked while stopped";
    return;
  }
  if (!s.timer->IsRunning()) {
    s.ResetTimer();
    LOGF(INFO) << "Resumed " << type << " monitor";
  }
}

void CameraMonitor::MonitorTimeoutOnThread(MonitorType type) {
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  DCHECK(monitor_states_.contains(type));

  State& s = monitor_states_.at(type);
  if (s.is_kicked) {
    s.ResetTimer();
  } else {
    LOGF(WARNING) << "No " << type << " for more than " << kMonitorTimeDelta;
    if (s.timeout_callback) {
      std::move(s.timeout_callback).Run();
    }
  }
}

CameraDeviceAdapter::CameraDeviceAdapter(
    camera3_device_t* camera_device,
    uint32_t device_api_version,
    const camera_metadata_t* static_info,
    base::RepeatingCallback<int(int)> get_internal_camera_id_callback,
    base::RepeatingCallback<int(int)> get_public_camera_id_callback,
    base::OnceCallback<void()> close_callback,
    std::unique_ptr<StreamManipulatorManager> stream_manipulator_manager,
    const bool async_capture_request_call)
    : camera_device_ops_thread_("CameraDeviceOpsThread"),
      camera_callback_ops_thread_("CameraCallbackOpsThread"),
      fence_sync_thread_("FenceSyncThread"),
      get_internal_camera_id_callback_(get_internal_camera_id_callback),
      get_public_camera_id_callback_(get_public_camera_id_callback),
      close_callback_(std::move(close_callback)),
      device_closed_(false),
      camera_device_(camera_device),
      device_api_version_(device_api_version),
      static_info_(static_info),
      camera_metrics_(CameraMetrics::New()),
      stream_manipulator_manager_(std::move(stream_manipulator_manager)),
      async_capture_request_call_(async_capture_request_call),
      inflight_requests_empty_cv_(&inflight_requests_lock_) {
  camera3_callback_ops_t::process_capture_result = ProcessCaptureResult;
  camera3_callback_ops_t::notify = Notify;

  std::optional<int32_t> partial_result_count =
      GetRoMetadata<int32_t>(static_info, ANDROID_REQUEST_PARTIAL_RESULT_COUNT);
  partial_result_count_ =
      base::checked_cast<uint32_t>(partial_result_count.value_or(1));
}

CameraDeviceAdapter::~CameraDeviceAdapter() {
  // Make sure that the camera is closed when the device adapter is destructed.
  camera_device_ops_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(base::IgnoreResult(&CameraDeviceAdapter::Close),
                                base::Unretained(this)));

  camera_device_ops_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraDeviceAdapter::ResetDeviceOpsDelegateOnThread,
                     base::Unretained(this)));
  camera_callback_ops_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraDeviceAdapter::ResetCallbackOpsDelegateOnThread,
                     base::Unretained(this)));
  camera_device_ops_thread_.Stop();
  camera_callback_ops_thread_.Stop();
}

bool CameraDeviceAdapter::Start() {
  if (!camera_device_ops_thread_.Start()) {
    LOGF(ERROR) << "Failed to start CameraDeviceOpsThread";
    return false;
  }
  if (!camera_callback_ops_thread_.Start()) {
    LOGF(ERROR) << "Failed to start CameraCallbackOpsThread";
    return false;
  }
  device_ops_delegate_ = std::make_unique<Camera3DeviceOpsDelegate>(
      this, camera_device_ops_thread_.task_runner());
  return true;
}

void CameraDeviceAdapter::Bind(
    mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver) {
  device_ops_delegate_->Bind(
      std::move(device_ops_receiver),
      // Close the device when the Mojo channel breaks.
      base::BindOnce(base::IgnoreResult(&CameraDeviceAdapter::Close),
                     base::Unretained(this)));
}

int32_t CameraDeviceAdapter::Initialize(
    mojo::PendingRemote<mojom::Camera3CallbackOps> callback_ops) {
  TRACE_HAL_ADAPTER();
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());

  if (device_closed_) {
    return -ENODEV;
  }

  {
    base::AutoLock l(fence_sync_thread_lock_);
    if (!fence_sync_thread_.Start()) {
      LOGF(ERROR) << "Fence sync thread failed to start";
      return -ENODEV;
    }
  }

  stream_manipulator_manager_->Initialize(
      static_info_, StreamManipulator::Callbacks{
                        .result_callback = base::BindRepeating(
                            CameraDeviceAdapter::ReturnResultToClient, this),
                        .notify_callback = base::BindRepeating(
                            CameraDeviceAdapter::NotifyClient, this)});

  base::AutoLock l(callback_ops_delegate_lock_);
  // Unlike the camera module, only one peer is allowed to access a camera
  // device at any time.
  DCHECK(!callback_ops_delegate_);
  callback_ops_delegate_ = std::make_unique<Camera3CallbackOpsDelegate>(
      camera_callback_ops_thread_.task_runner());
  callback_ops_delegate_->Bind(
      std::move(callback_ops),
      base::BindOnce(&CameraDeviceAdapter::ResetCallbackOpsDelegateOnThread,
                     base::Unretained(this)));
  {
    TRACE_HAL_ADAPTER_EVENT("HAL::Initialize");
    return camera_device_->ops->initialize(camera_device_, this);
  }
}

int32_t CameraDeviceAdapter::ConfigureStreams(
    mojom::Camera3StreamConfigurationPtr config,
    mojom::Camera3StreamConfigurationPtr* updated_config) {
  TRACE_HAL_ADAPTER();
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());

  if (device_closed_) {
    return -ENODEV;
  }

  base::ElapsedTimer timer;

  {
    base::AutoLock l(inflight_requests_lock_);
    inflight_requests_.clear();
  }

  base::AutoLock l(streams_lock_);

  // Free previous allocated buffers before new allocation.
  FreeAllocatedStreamBuffers();

  internal::ScopedStreams new_streams;
  StreamEffectMap stream_effects_map;
  for (const auto& s : config->streams) {
    LOGF(INFO) << "id = " << s->id << ", type = " << s->stream_type
               << ", size = " << s->width << "x" << s->height
               << ", format = " << s->format;
    uint64_t id = s->id;
    auto& stream = new_streams[id];
    stream = std::make_unique<internal::camera3_stream_aux_t>();
    memset(stream.get(), 0, sizeof(*stream.get()));
    stream->stream_type = static_cast<camera3_stream_type_t>(s->stream_type);
    stream->width = s->width;
    stream->height = s->height;
    stream->format = static_cast<int32_t>(s->format);
    stream->usage = s->usage;
    stream->max_buffers = s->max_buffers;
    stream->data_space = static_cast<android_dataspace_t>(s->data_space);
    stream->rotation = static_cast<camera3_stream_rotation_t>(s->rotation);
    if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
      DCHECK(s->physical_camera_id.has_value());
      if (s->physical_camera_id.value() != "") {
        int public_camera_id;
        if (!base::StringToInt(s->physical_camera_id.value(),
                               &public_camera_id)) {
          LOGF(ERROR) << "Invalid physical camera ID: "
                      << s->physical_camera_id.value();
          return -EINVAL;
        }
        int internal_camera_id =
            get_internal_camera_id_callback_.Run(public_camera_id);
        if (internal_camera_id == -1) {
          LOGF(ERROR) << "Failed to find internal camera ID for camera "
                      << public_camera_id;
          return -EINVAL;
        }
        stream->physical_camera_id_string =
            base::NumberToString(internal_camera_id);
      } else {
        stream->physical_camera_id_string = "";
      }
      stream->physical_camera_id = stream->physical_camera_id_string.c_str();
    }
    stream->crop_rotate_scale_degrees = 0;
    if (s->crop_rotate_scale_info) {
      stream->crop_rotate_scale_degrees =
          static_cast<camera3_stream_rotation_t>(
              s->crop_rotate_scale_info->crop_rotate_scale_degrees);
    }
    if (s->effects) {
      for (const auto& effect : *s->effects) {
        switch (effect->which()) {
          case mojom::Camera3StreamEffect::Tag::kUnknownConfig:
            LOGF(WARNING) << "Unknown effect set in stream " << s->id
                          << "; skipped";
            break;
          case mojom::Camera3StreamEffect::Tag::kPortraitModeConfig:
            auto portrait_mode_effect =
                std::make_unique<PortraitModeStreamEffect>();
            portrait_mode_effect->type = StreamEffectType::kPortraitMode;
            portrait_mode_effect->enable_rectiface =
                effect->get_portrait_mode_config()->enable_rectiface;

            stream_effects_map[stream.get()].push_back(
                std::move(portrait_mode_effect));
            break;
        }
      }
    }

    // Currently we are not interest in the resolution of input stream and
    // bidirectional stream.
    if (stream->stream_type == CAMERA3_STREAM_OUTPUT) {
      camera_metrics_->SendConfigureStreamResolution(
          stream->width, stream->height, stream->format);
    }
  }
  streams_.swap(new_streams);

  std::vector<camera3_stream_t*> streams_ptr;
  for (const auto& s : streams_) {
    streams_ptr.push_back(s.second.get());
  }
  internal::ScopedCameraMetadata session_parameters;
  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    session_parameters =
        internal::DeserializeCameraMetadata(config->session_parameters);
  }
  Camera3StreamConfiguration stream_config(camera3_stream_configuration_t{
      .num_streams = static_cast<uint32_t>(streams_ptr.size()),
      .streams = streams_ptr.data(),
      .operation_mode = static_cast<camera3_stream_configuration_mode_t>(
          config->operation_mode),
      .session_parameters = session_parameters.get(),
  });

  // TODO(kamesan): Handle the failures.
  stream_manipulator_manager_->ConfigureStreams(&stream_config,
                                                &stream_effects_map);

  int32_t result = 0;
  {
    TRACE_HAL_ADAPTER_EVENT("HAL::ConfigureStreams");
    camera3_stream_configuration_t* raw_config = stream_config.Lock();
    result = camera_device_->ops->configure_streams(camera_device_, raw_config);
    stream_config.Unlock();
  }

  stream_manipulator_manager_->OnConfiguredStreams(&stream_config);

  if (result == 0) {
    *updated_config = mojom::Camera3StreamConfiguration::New();
    (*updated_config)->operation_mode = config->operation_mode;
    if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
      (*updated_config)->session_parameters =
          std::move(config->session_parameters);
    }
    for (const auto& s : streams_) {
      mojom::Camera3StreamPtr ptr = mojom::Camera3Stream::New();
      ptr->id = s.first;
      ptr->format = static_cast<mojom::HalPixelFormat>(s.second->format);
      ptr->width = s.second->width;
      ptr->height = s.second->height;
      ptr->stream_type =
          static_cast<mojom::Camera3StreamType>(s.second->stream_type);
      ptr->data_space = s.second->data_space;
      // HAL should only change usage and max_buffers.
      ptr->usage = s.second->usage;
      ptr->max_buffers = s.second->max_buffers;
      ptr->crop_rotate_scale_info = mojom::CropRotateScaleInfo::New(
          static_cast<mojom::Camera3StreamRotation>(
              s.second->crop_rotate_scale_degrees));
      if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
        if (strlen(s.second->physical_camera_id) == 0) {
          ptr->physical_camera_id = "";
        } else {
          int internal_camera_id = 0;
          if (!base::StringToInt(s.second->physical_camera_id,
                                 &internal_camera_id)) {
            LOGF(ERROR) << "Invalid physical camera ID: "
                        << s.second->physical_camera_id;
            return -EINVAL;
          }
          int public_camera_id =
              get_public_camera_id_callback_.Run(internal_camera_id);
          if (public_camera_id == -1) {
            LOGF(ERROR)
                << "Failed to find public camera ID for internal camera "
                << internal_camera_id;
            return -EINVAL;
          }
          ptr->physical_camera_id = base::NumberToString(public_camera_id);
        }
      }
      (*updated_config)->streams.push_back(std::move(ptr));
    }

    base::RepeatingClosure timeout_callback = base::NullCallback();
    std::unique_ptr<CameraConfig> config =
        CameraConfig::Create(constants::kCrosCameraTestConfigPathString);
    if (config->GetBoolean(constants::kCrosAbortWhenCaptureMonitorTimeout,
                           false)) {
      timeout_callback = base::BindRepeating([]() { abort(); });
    }
    capture_monitor_.StartMonitor(CameraMonitor::MonitorType::kRequestsMonitor,
                                  timeout_callback);
    capture_monitor_.StartMonitor(CameraMonitor::MonitorType::kResultsMonitor,
                                  timeout_callback);
  }

  camera_metrics_->SendConfigureStreamsLatency(timer.Elapsed());

  return result;
}

mojom::CameraMetadataPtr CameraDeviceAdapter::ConstructDefaultRequestSettings(
    mojom::Camera3RequestTemplate type) {
  TRACE_HAL_ADAPTER();
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());

  if (device_closed_) {
    return mojom::CameraMetadata::New();
  }

  size_t type_index = static_cast<size_t>(type);
  if (type_index >= CAMERA3_TEMPLATE_COUNT) {
    LOGF(ERROR) << "Invalid template index given";
    return mojom::CameraMetadata::New();
  }
  android::CameraMetadata& request_template = request_templates_[type_index];
  if (request_template.isEmpty()) {
    int32_t request_type = static_cast<int32_t>(type);
    request_template.acquire(clone_camera_metadata(
        camera_device_->ops->construct_default_request_settings(camera_device_,
                                                                request_type)));
    stream_manipulator_manager_->ConstructDefaultRequestSettings(
        &request_template, request_type);
  }
  return internal::SerializeCameraMetadata(request_template.getAndLock());
}

int32_t CameraDeviceAdapter::ProcessCaptureRequest(
    mojom::Camera3CaptureRequestPtr request) {
  TRACE_HAL_ADAPTER("frame_number", request->frame_number);
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());

  if (device_closed_) {
    return -ENODEV;
  }

  camera3_capture_request_t req;
  req.frame_number = request->frame_number;

  internal::ScopedCameraMetadata settings =
      internal::DeserializeCameraMetadata(request->settings);
  if (settings) {
    capture_settings_ = std::move(settings);
  }

  capture_monitor_.Kick(CameraMonitor::MonitorType::kRequestsMonitor);

  // Need to keep track any registered buffers in case we need to cancel
  // the process_capture_request, so we can deregister them.
  std::vector<std::pair<uint64_t, const camera3_stream_buffer_t&>>
      registered_buffers;
  // Must hold the buffer_handles_lock_ before running this task.
  base::OnceClosure error_task_locked = base::BindOnce(
      [](CameraDeviceAdapter* self,
         const mojom::Camera3CaptureRequestPtr& request_ptr,
         const std::vector<std::pair<uint64_t, const camera3_stream_buffer_t&>>&
             registered_buffers) {
        if (registered_buffers.size() > 0) {
          self->buffer_handles_lock_.AssertAcquired();
          self->CancelBuffersRegistrationLocked(registered_buffers);
        }
        if (self->async_capture_request_call_) {
          self->NotifyInvalidCaptureRequest(request_ptr);
        }
      },
      base::Unretained(this), std::cref(request),
      std::cref(registered_buffers));

  std::vector<const char*> phys_ids;
  std::vector<std::string> phys_ids_string;
  std::vector<const camera_metadata_t*> phys_settings;
  std::vector<internal::ScopedCameraMetadata> phys_settings_scoped;
  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    DCHECK(request->physcam_settings.has_value());
    req.num_physcam_settings = request->physcam_settings.value().size();
    if (req.num_physcam_settings > 0) {
      for (int i = 0; i < req.num_physcam_settings; ++i) {
        int public_camera_id = request->physcam_settings.value()[i]->id;
        int internal_camera_id =
            get_internal_camera_id_callback_.Run(public_camera_id);
        if (internal_camera_id == -1) {
          LOGF(ERROR) << "Failed to find internal camera ID for camera "
                      << public_camera_id;
          base::AutoLock buffer_handles_lock(buffer_handles_lock_);
          std::move(error_task_locked).Run();
          return -EINVAL;
        }
        phys_ids_string.push_back(base::NumberToString(internal_camera_id));
        phys_settings_scoped.push_back(internal::DeserializeCameraMetadata(
            request->physcam_settings.value()[i]->metadata));
      }
      for (const auto& id : phys_ids_string) {
        phys_ids.push_back(id.c_str());
      }
      for (const auto& setting : phys_settings_scoped) {
        phys_settings.push_back(setting.get());
      }
      req.physcam_id = phys_ids.data();
      req.physcam_settings = phys_settings.data();
    } else {
      req.physcam_id = nullptr;
      req.physcam_settings = nullptr;
    }
  }

  // Deserialize input buffer.
  buffer_handle_t input_buffer_handle;
  camera3_stream_buffer_t input_buffer;
  if (!request->input_buffer.is_null()) {
    base::AutoLock buffer_handles_lock(buffer_handles_lock_);
    if (request->input_buffer->buffer_handle) {
      if (RegisterBufferLocked(
              std::move(request->input_buffer->buffer_handle))) {
        LOGF(ERROR) << "Failed to register input buffer";
        std::move(error_task_locked).Run();
        return -EINVAL;
      }
    }
    input_buffer.buffer =
        const_cast<const native_handle_t**>(&input_buffer_handle);
    {
      base::AutoLock streams_lock(streams_lock_);
      internal::DeserializeStreamBuffer(request->input_buffer, streams_,
                                        buffer_handles_, &input_buffer);
    }
    req.input_buffer = &input_buffer;
    registered_buffers.emplace_back(request->input_buffer->buffer_id,
                                    *req.input_buffer);
  } else {
    req.input_buffer = nullptr;
  }

  // Deserialize output buffers.
  size_t num_output_buffers = request->output_buffers.size();
  DCHECK_GT(num_output_buffers, 0);

  std::vector<camera3_stream_buffer_t> output_buffers(num_output_buffers);
  {
    base::AutoLock buffer_handles_lock(buffer_handles_lock_);
    for (size_t i = 0; i < num_output_buffers; ++i) {
      mojom::Camera3StreamBufferPtr& out_buf_ptr = request->output_buffers[i];
      if (out_buf_ptr->buffer_handle) {
        if (RegisterBufferLocked(std::move(out_buf_ptr->buffer_handle))) {
          LOGF(ERROR) << "Failed to register output buffer";
          std::move(error_task_locked).Run();
          return -EINVAL;
        }
      }
      {
        base::AutoLock streams_lock(streams_lock_);
        internal::DeserializeStreamBuffer(
            out_buf_ptr, streams_, buffer_handles_, &output_buffers.at(i));
      }
      registered_buffers.emplace_back(request->output_buffers[i]->buffer_id,
                                      output_buffers.at(i));
    }
    req.num_output_buffers = output_buffers.size();
    req.output_buffers =
        const_cast<const camera3_stream_buffer_t*>(output_buffers.data());
  }

  req.settings = capture_settings_.get();

  // TODO(jcliang): We may need to cache the last request settings here. In case
  // where the client sets a null settings we can pass the cached settings to
  // the stream manipulators so that they can still do incremental changes on
  // top of the cached settings.
  Camera3CaptureDescriptor request_descriptor(req);

  for (const auto& output_buffer : request_descriptor.GetOutputBuffers()) {
    TRACE_HAL_ADAPTER_BEGIN(
        ToString(HalAdapterTraceEvent::kCapture),
        GetTraceTrack(HalAdapterTraceEvent::kCapture,
                      request_descriptor.frame_number(),
                      reinterpret_cast<uintptr_t>(*output_buffer.buffer())),
        "frame_number", request_descriptor.frame_number(), "stream",
        reinterpret_cast<uintptr_t>(output_buffer.stream()), "width",
        output_buffer.stream()->width, "height", output_buffer.stream()->height,
        "format", output_buffer.stream()->format);
  }
  {
    base::AutoLock l(inflight_requests_lock_);
    CHECK(inflight_requests_.find(request->frame_number) ==
          inflight_requests_.end());
    base::flat_set<const camera3_stream_t*> pending_streams;
    if (const auto* b = request_descriptor.GetInputBuffer()) {
      pending_streams.insert(b->stream());
    }
    for (const auto& b : request_descriptor.GetOutputBuffers()) {
      pending_streams.insert(b.stream());
    }
    inflight_requests_.emplace(
        request->frame_number,
        InflightRequestInfo{
            .pending_streams = std::move(pending_streams),
            .has_pending_metadata = true,
        });
    DVLOGF(2) << "Inflight requests ++: " << inflight_requests_.size();
  }

  stream_manipulator_manager_->ProcessCaptureRequest(&request_descriptor);
  {
    TRACE_HAL_ADAPTER_EVENT("HAL::ProcessCaptureRequest",
                            [&](perfetto::EventContext ctx) {
                              request_descriptor.PopulateEventAnnotation(ctx);
                            });
    int ret = camera_device_->ops->process_capture_request(
        camera_device_, request_descriptor.LockForRequest());
    if (ret != 0) {
      base::AutoLock buffer_handles_lock(buffer_handles_lock_);
      std::move(error_task_locked).Run();
    }
    return ret;
  }
}

void CameraDeviceAdapter::Dump(mojo::ScopedHandle fd) {
  TRACE_HAL_ADAPTER();
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());

  if (device_closed_) {
    return;
  }

  base::ScopedFD dump_fd(mojo::UnwrapPlatformHandle(std::move(fd)).TakeFD());
  camera_device_->ops->dump(camera_device_, dump_fd.get());
}

int32_t CameraDeviceAdapter::Flush() {
  TRACE_HAL_ADAPTER();
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());

  if (device_closed_) {
    return -ENODEV;
  }

  // By Android spec flush() must return in 1000ms.
  constexpr base::TimeDelta kFlushTimeout = base::Milliseconds(1000);
  base::ElapsedTimer timer;

  const int32_t ret = camera_device_->ops->flush(camera_device_);
  if (ret != 0) {
    LOGF(ERROR) << "flush() failed with status " << ret;
    return ret;
  }
  stream_manipulator_manager_->Flush();

  {
    base::AutoLock l(inflight_requests_lock_);
    while (!inflight_requests_.empty()) {
      const base::TimeDelta elapsed_time = timer.Elapsed();
      if (elapsed_time >= kFlushTimeout) {
        LOGF(ERROR) << "Flushing pending requests timed out";
        return -ENODEV;
      }
      inflight_requests_empty_cv_.TimedWait(kFlushTimeout - elapsed_time);
    }
  }
  return 0;
}

int32_t CameraDeviceAdapter::RegisterBuffer(
    uint64_t buffer_id,
    mojom::Camera3DeviceOps::BufferType type,
    std::vector<mojo::ScopedHandle> fds,
    uint32_t drm_format,
    mojom::HalPixelFormat hal_pixel_format,
    uint32_t width,
    uint32_t height,
    const std::vector<uint32_t>& strides,
    const std::vector<uint32_t>& offsets,
    uint64_t modifier) {
  TRACE_HAL_ADAPTER();

  base::AutoLock l(buffer_handles_lock_);
  return CameraDeviceAdapter::RegisterBufferLocked(
      buffer_id, std::move(fds), drm_format, hal_pixel_format, width, height,
      strides, offsets, modifier);
}

int32_t CameraDeviceAdapter::Close() {
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  if (device_closed_) {
    return 0;
  }
  device_closed_ = true;

  // Stop the capture monitors before closing the streams in case it takes time
  // and triggers the timeout.
  capture_monitor_.StopMonitor(CameraMonitor::MonitorType::kRequestsMonitor);
  capture_monitor_.StopMonitor(CameraMonitor::MonitorType::kResultsMonitor);

  int32_t ret = 0;
  {
    TRACE_HAL_ADAPTER_EVENT("HAL::Close");
    ret = camera_device_->common.close(&camera_device_->common);
    DCHECK_EQ(ret, 0);
  }
  {
    base::AutoLock l(fence_sync_thread_lock_);
    fence_sync_thread_.Stop();
  }
  FreeAllocatedStreamBuffers();

  // Ensure that no more stream manipulator operations happen after the device
  // is closed.
  stream_manipulator_manager_.reset();

  std::move(close_callback_).Run();
  return ret;
}

int32_t CameraDeviceAdapter::ConfigureStreamsAndGetAllocatedBuffers(
    mojom::Camera3StreamConfigurationPtr config,
    mojom::Camera3StreamConfigurationPtr* updated_config,
    AllocatedBuffers* allocated_buffers) {
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  int32_t result = ConfigureStreams(std::move(config), updated_config);

  // Early return if configure streams failed.
  if (result) {
    return result;
  }

  bool is_success =
      AllocateBuffersForStreams((*updated_config)->streams, allocated_buffers);

  if (!is_success) {
    FreeAllocatedStreamBuffers();
  }

  return result;
}

bool CameraDeviceAdapter::IsRequestOrResultStalling() {
  return !capture_monitor_.HasBeenKicked(
             CameraMonitor::MonitorType::kRequestsMonitor) ||
         !capture_monitor_.HasBeenKicked(
             CameraMonitor::MonitorType::kResultsMonitor);
}

void CameraDeviceAdapter::ForceClose() {
  camera_device_ops_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraDeviceAdapter::ForceCloseOnDeviceOpsThread,
                     base::Unretained(this)));
}

// static
void CameraDeviceAdapter::ProcessCaptureResult(
    const camera3_callback_ops_t* ops, const camera3_capture_result_t* result) {
  TRACE_HAL_ADAPTER([&](perfetto::EventContext ctx) {
    ctx.AddDebugAnnotation("frame_number", result->frame_number);
    if (result->input_buffer != nullptr) {
      perfetto::Flow::ProcessScoped(
          reinterpret_cast<uintptr_t>(*result->input_buffer->buffer))(ctx);
    }
    for (int i = 0; i < result->num_output_buffers; ++i) {
      perfetto::Flow::ProcessScoped(
          reinterpret_cast<uintptr_t>(*result->output_buffers[i].buffer))(ctx);
    }
  });

  CameraDeviceAdapter* self = const_cast<CameraDeviceAdapter*>(
      static_cast<const CameraDeviceAdapter*>(ops));

  self->capture_monitor_.Kick(CameraMonitor::MonitorType::kResultsMonitor);

  self->stream_manipulator_manager_->ProcessCaptureResult(
      Camera3CaptureDescriptor(*result));
}

// static
void CameraDeviceAdapter::ReturnResultToClient(
    const camera3_callback_ops_t* ops,
    Camera3CaptureDescriptor result_descriptor) {
  TRACE_HAL_ADAPTER([&](perfetto::EventContext ctx) {
    result_descriptor.PopulateEventAnnotation(ctx);
  });

  if (!result_descriptor.has_metadata() &&
      !result_descriptor.has_input_buffer() &&
      result_descriptor.num_output_buffers() == 0) {
    // Android camera framework doesn't accept empty capture results. Since ZSL
    // would remove the input buffer, output buffers and metadata it added, it's
    // possible that we end up with an empty capture result.
    VLOGFID(1, result_descriptor.frame_number()) << "Drop empty capture result";
    return;
  }

  CameraDeviceAdapter* self = const_cast<CameraDeviceAdapter*>(
      static_cast<const CameraDeviceAdapter*>(ops));
  {
    base::AutoLock l(self->inflight_requests_lock_);
    auto it = self->inflight_requests_.find(result_descriptor.frame_number());
    if (it != self->inflight_requests_.end()) {
      InflightRequestInfo& info = it->second;
      if (const auto* b = result_descriptor.GetInputBuffer()) {
        info.pending_streams.erase(b->stream());
      }
      for (const auto& b : result_descriptor.GetOutputBuffers()) {
        info.pending_streams.erase(b.stream());
      }
      if (result_descriptor.partial_result() == self->partial_result_count_) {
        info.has_pending_metadata = false;
      }
      if (info.pending_streams.empty() && !info.has_pending_metadata) {
        self->inflight_requests_.erase(it);
        DVLOGF(2) << "Inflight requests --: "
                  << self->inflight_requests_.size();
        if (self->inflight_requests_.empty()) {
          self->inflight_requests_empty_cv_.Signal();
        }
      }
    }
  }
  mojom::Camera3CaptureResultPtr result_ptr;
  camera3_capture_result_t* locked_result = result_descriptor.LockForResult();
  result_ptr = self->PrepareCaptureResult(locked_result);
  result_descriptor.Unlock();

  // process_capture_result may be called multiple times for a single frame,
  // each time with a new disjoint piece of metadata and/or set of gralloc
  // buffers. The framework will accumulate these partial metadata results into
  // one result.
  // ref:
  // https://android.googlesource.com/platform/hardware/libhardware/+/8a6fed0d280014d84fe0f6a802f1cf29600e5bae/include/hardware/camera3.h#284
  for (const auto& output_buffer : result_descriptor.GetOutputBuffers()) {
    TRACE_HAL_ADAPTER_END(GetTraceTrack(
        HalAdapterTraceEvent::kCapture, result_descriptor.frame_number(),
        reinterpret_cast<uintptr_t>(*output_buffer.buffer())));
  }

  base::AutoLock l(self->callback_ops_delegate_lock_);
  if (self->callback_ops_delegate_) {
    self->callback_ops_delegate_->ProcessCaptureResult(std::move(result_ptr));
  }
}

// Asserts that the offset and size of the |frame_number| member are the same in
// both the shutter and error message, so that we can access the |frame_number|
// using either member in the |camera3_notify_msg_t::message| union regardless
// of the type of the notify message.
static_assert(offsetof(camera3_shutter_msg_t, frame_number) ==
              offsetof(camera3_error_msg_t, frame_number));
static_assert(sizeof(camera3_shutter_msg_t::frame_number) ==
              sizeof(camera3_error_msg_t::frame_number));

// static
void CameraDeviceAdapter::Notify(const camera3_callback_ops_t* ops,
                                 const camera3_notify_msg_t* msg) {
  CHECK(msg);
  TRACE_HAL_ADAPTER([&](perfetto::EventContext ctx) {
    ctx.AddDebugAnnotation("frame_number", GetFrameNumber(*msg));
    ctx.AddDebugAnnotation("type", msg->type);
    switch (msg->type) {
      case CAMERA3_MSG_SHUTTER:
        ctx.AddDebugAnnotation("shutter_timestamp",
                               msg->message.shutter.timestamp);
        break;
      case CAMERA3_MSG_ERROR:
        ctx.AddDebugAnnotation(
            "error_stream",
            reinterpret_cast<uintptr_t>(msg->message.error.error_stream));
        ctx.AddDebugAnnotation("error_code", msg->message.error.error_code);
        break;
    }
  });

  CameraDeviceAdapter* self = const_cast<CameraDeviceAdapter*>(
      static_cast<const CameraDeviceAdapter*>(ops));

  if (msg->type == CAMERA3_MSG_ERROR) {
    self->camera_metrics_->SendError(msg->message.error.error_code);
    if (msg->message.error.error_code == CAMERA3_MSG_ERROR_DEVICE) {
      LOGF(ERROR) << "Fatal device error; aborting the camera service";
      _exit(EIO);
    }
  }

  self->stream_manipulator_manager_->Notify(*msg);
}

// static
void CameraDeviceAdapter::NotifyClient(const camera3_callback_ops_t* ops,
                                       camera3_notify_msg_t msg) {
  TRACE_HAL_ADAPTER("frame_number", GetFrameNumber(msg));

  CameraDeviceAdapter* self = const_cast<CameraDeviceAdapter*>(
      static_cast<const CameraDeviceAdapter*>(ops));
  if (msg.type == CAMERA3_MSG_ERROR) {
    base::AutoLock l(self->inflight_requests_lock_);
    auto it = self->inflight_requests_.find(msg.message.error.frame_number);
    if (it != self->inflight_requests_.end()) {
      InflightRequestInfo& info = it->second;
      switch (msg.message.error.error_code) {
        case CAMERA3_MSG_ERROR_REQUEST:
        case CAMERA3_MSG_ERROR_RESULT:
          // Some partial metadata won't be available, so stop tracking it.
          // For request error, HAL still returns buffers with capture results.
          info.has_pending_metadata = false;
          break;
        case CAMERA3_MSG_ERROR_BUFFER:
          info.pending_streams.erase(msg.message.error.error_stream);
          break;
      }
      if (info.pending_streams.empty() && !info.has_pending_metadata) {
        self->inflight_requests_.erase(it);
        DVLOGF(2) << "Inflight requests --: "
                  << self->inflight_requests_.size();
        if (self->inflight_requests_.empty()) {
          self->inflight_requests_empty_cv_.Signal();
        }
      }
    }
  }
  mojom::Camera3NotifyMsgPtr msg_ptr = self->PrepareNotifyMsg(&msg);
  base::AutoLock l(self->callback_ops_delegate_lock_);
  if (self->callback_ops_delegate_) {
    self->callback_ops_delegate_->Notify(std::move(msg_ptr));
  }
}

void CameraDeviceAdapter::NotifyInvalidCaptureRequest(
    const mojom::Camera3CaptureRequestPtr& request_ptr) {
  DCHECK(async_capture_request_call_);
  TRACE_HAL_ADAPTER();

  mojom::Camera3CaptureResultPtr result_ptr =
      mojom::Camera3CaptureResult::New();
  result_ptr->frame_number = request_ptr->frame_number;
  result_ptr->result = mojom::CameraMetadata::New();
  result_ptr->result->size = 0;
  result_ptr->result->entry_count = 0;
  result_ptr->result->entry_capacity = 0;
  result_ptr->result->data_count = 0;
  result_ptr->result->data_capacity = 0;
  result_ptr->partial_result = 0;
  result_ptr->output_buffers = std::move(request_ptr->output_buffers);
  for (const auto& out_buf : *result_ptr->output_buffers) {
    out_buf->release_fence = std::move(out_buf->acquire_fence);
    out_buf->buffer_handle = nullptr;
    out_buf->status = mojom::Camera3BufferStatus::CAMERA3_BUFFER_STATUS_ERROR;
  }
  if (!request_ptr->input_buffer.is_null()) {
    result_ptr->input_buffer = std::move(request_ptr->input_buffer);
    result_ptr->input_buffer->release_fence =
        std::move(result_ptr->input_buffer->acquire_fence);
    result_ptr->input_buffer->buffer_handle = nullptr;
  }

  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    result_ptr->physcam_metadata =
        std::vector<mojom::Camera3PhyscamMetadataPtr>();
  }

  camera3_notify_msg_t invalid_request_msg = {
      .type = CAMERA3_MSG_ERROR,
      .message =
          {
              .error =
                  {
                      .frame_number = request_ptr->frame_number,
                      .error_code = CAMERA3_MSG_ERROR_REQUEST,
                  },
          },
  };

  base::AutoLock l(callback_ops_delegate_lock_);
  mojom::Camera3NotifyMsgPtr msg_ptr = PrepareNotifyMsg(&invalid_request_msg);
  if (callback_ops_delegate_) {
    callback_ops_delegate_->Notify(std::move(msg_ptr));
  }
  if (callback_ops_delegate_) {
    callback_ops_delegate_->ProcessCaptureResult(std::move(result_ptr));
  }
}

bool CameraDeviceAdapter::AllocateBuffersForStreams(
    const std::vector<mojom::Camera3StreamPtr>& streams,
    AllocatedBuffers* allocated_buffers) {
  TRACE_HAL_ADAPTER();

  AllocatedBuffers tmp_allocated_buffers;
  auto* camera_buffer_manager = CameraBufferManager::GetInstance();
  for (const auto& stream : streams) {
    std::vector<mojom::Camera3StreamBufferPtr> new_buffers;
    uint32_t stream_format = static_cast<uint32_t>(stream->format);
    uint64_t stream_id = stream->id;
    DCHECK(stream_format == HAL_PIXEL_FORMAT_BLOB ||
           stream_format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED ||
           stream_format == HAL_PIXEL_FORMAT_YCbCr_420_888);
    uint32_t buffer_width;
    uint32_t buffer_height;
    int status;
    if (stream_format == HAL_PIXEL_FORMAT_BLOB) {
      camera_metadata_ro_entry entry;
      status = find_camera_metadata_ro_entry(static_info_,
                                             ANDROID_JPEG_MAX_SIZE, &entry);
      if (status) {
        LOGF(ERROR) << "No Jpeg max size information in metadata.";
        return false;
      }
      buffer_width = entry.data.i32[0];
      buffer_height = 1;
    } else {
      buffer_width = stream->width;
      buffer_height = stream->height;
    }
    for (size_t i = 0; i < stream->max_buffers; i++) {
      mojom::Camera3StreamBufferPtr new_buffer =
          mojom::Camera3StreamBuffer::New();
      new_buffer->stream_id = stream_id;

      mojom::CameraBufferHandlePtr mojo_buffer_handle =
          mojom::CameraBufferHandle::New();

      buffer_handle_t buffer_handle;
      uint32_t buffer_stride;
      status = camera_buffer_manager->Allocate(buffer_width, buffer_height,
                                               stream_format, stream->usage,
                                               &buffer_handle, &buffer_stride);
      if (status) {
        LOGF(ERROR) << "Failed to allocate buffer.";
        return false;
      }

      mojo_buffer_handle->width = buffer_width;
      mojo_buffer_handle->height = buffer_height;
      mojo_buffer_handle->drm_format =
          camera_buffer_manager->ResolveDrmFormat(stream_format, stream->usage);
      CHECK_NE(mojo_buffer_handle->drm_format, 0);

      auto num_planes = CameraBufferManager::GetNumPlanes(buffer_handle);
      mojo_buffer_handle->sizes = std::vector<uint32_t>();
      for (size_t plane = 0; plane < num_planes; plane++) {
        auto dup_fd = DupWithCloExec(buffer_handle->data[plane]);
        CHECK(dup_fd.is_valid());
        mojo_buffer_handle->fds.push_back(
            mojo::WrapPlatformFile(std::move(dup_fd)));
        mojo_buffer_handle->strides.push_back(
            CameraBufferManager::GetPlaneStride(buffer_handle, plane));
        mojo_buffer_handle->offsets.push_back(
            CameraBufferManager::GetPlaneOffset(buffer_handle, plane));
        mojo_buffer_handle->sizes->push_back(
            CameraBufferManager::GetPlaneSize(buffer_handle, plane));
      }

      auto* camera_buffer_handle =
          camera_buffer_handle_t::FromBufferHandle(buffer_handle);
      uint64_t buffer_id = camera_buffer_handle->buffer_id;
      mojo_buffer_handle->buffer_id = buffer_id;
      mojo_buffer_handle->hal_pixel_format = stream->format;

      new_buffer->buffer_id = buffer_id;
      new_buffer->buffer_handle = std::move(mojo_buffer_handle);
      new_buffers.push_back(std::move(new_buffer));

      allocated_stream_buffers_[buffer_id] = std::move(buffer_handle);
    }
    tmp_allocated_buffers.insert(
        std::pair<uint64_t, std::vector<mojom::Camera3StreamBufferPtr>>(
            stream_id, std::move(new_buffers)));
  }
  *allocated_buffers = std::move(tmp_allocated_buffers);
  return true;
}

void CameraDeviceAdapter::FreeAllocatedStreamBuffers() {
  TRACE_HAL_ADAPTER();

  auto camera_buffer_manager = CameraBufferManager::GetInstance();
  if (allocated_stream_buffers_.empty()) {
    return;
  }

  for (auto it : allocated_stream_buffers_) {
    camera_buffer_manager->Free(it.second);
  }
  allocated_stream_buffers_.clear();
}

int32_t CameraDeviceAdapter::RegisterBufferLocked(
    uint64_t buffer_id,
    std::vector<mojo::ScopedHandle> fds,
    uint32_t drm_format,
    mojom::HalPixelFormat hal_pixel_format,
    uint32_t width,
    uint32_t height,
    const std::vector<uint32_t>& strides,
    const std::vector<uint32_t>& offsets,
    uint64_t modifier) {
  size_t num_planes = fds.size();
  CHECK_LE(num_planes, kMaxPlanes);
  std::unique_ptr<camera_buffer_handle_t> buffer_handle =
      std::make_unique<camera_buffer_handle_t>();
  buffer_handle->base.version = sizeof(buffer_handle->base);
  buffer_handle->base.numFds = kCameraBufferHandleNumFds;
  buffer_handle->base.numInts = kCameraBufferHandleNumInts;

  buffer_handle->magic = kCameraBufferMagic;
  buffer_handle->buffer_id = buffer_id;
  buffer_handle->drm_format = drm_format;
  buffer_handle->hal_pixel_format = static_cast<uint32_t>(hal_pixel_format);
  buffer_handle->width = width;
  buffer_handle->height = height;
  for (size_t i = 0; i < num_planes; ++i) {
    buffer_handle->fds[i] =
        mojo::UnwrapPlatformHandle(std::move(fds[i])).ReleaseFD();
    buffer_handle->strides[i] = strides[i];
    buffer_handle->offsets[i] = offsets[i];
  }
  buffer_handle->modifier = modifier;

  if (!CameraBufferManager::GetInstance()->IsValidBuffer(buffer_handle->self)) {
    LOGF(ERROR) << "Invalid buffer handle";
    return -EINVAL;
  }

  buffer_handles_[buffer_id] = std::move(buffer_handle);

  VLOGF(1) << std::hex << "Buffer 0x" << buffer_id << " registered: "
           << "format: " << FormatToString(drm_format)
           << " dimension: " << std::dec << width << "x" << height
           << " num_planes: " << num_planes << " modifier: " << modifier;
  return 0;
}

int32_t CameraDeviceAdapter::RegisterBufferLocked(
    mojom::CameraBufferHandlePtr buffer) {
  // For the external buffer without providing modifier information, we using
  // DRM_FORMAT_MOD_LINEAR as the default fallback format to consistent with
  // previous behavior.
  return RegisterBufferLocked(
      buffer->buffer_id, std::move(buffer->fds), buffer->drm_format,
      buffer->hal_pixel_format, buffer->width, buffer->height, buffer->strides,
      buffer->offsets,
      buffer->has_modifier ? buffer->modifier : DRM_FORMAT_MOD_LINEAR);
}

mojom::Camera3CaptureResultPtr CameraDeviceAdapter::PrepareCaptureResult(
    const camera3_capture_result_t* result) {
  mojom::Camera3CaptureResultPtr r = mojom::Camera3CaptureResult::New();

  r->frame_number = result->frame_number;
  r->result = internal::SerializeCameraMetadata(result->result);
  r->partial_result = result->partial_result;

  // Serialize output buffers.  This may be none as num_output_buffers may be 0.
  if (result->output_buffers) {
    base::AutoLock buffer_handles_lock(buffer_handles_lock_);
    base::AutoLock streams_lock(streams_lock_);
    std::vector<mojom::Camera3StreamBufferPtr> output_buffers;
    for (size_t i = 0; i < result->num_output_buffers; i++) {
      mojom::Camera3StreamBufferPtr out_buf = internal::SerializeStreamBuffer(
          result->output_buffers + i, streams_, buffer_handles_);
      if (out_buf.is_null()) {
        LOGF(ERROR) << "Failed to serialize output stream buffer";
        // TODO(jcliang): Handle error?
      }
      RemoveReturnBufferLocked(out_buf->buffer_id,
                               *(result->output_buffers + i));
      output_buffers.push_back(std::move(out_buf));
    }
    if (output_buffers.size() > 0) {
      r->output_buffers = std::move(output_buffers);
    }
  }

  // Serialize input buffer.
  if (result->input_buffer) {
    base::AutoLock buffer_handles_lock(buffer_handles_lock_);
    base::AutoLock streams_lock(streams_lock_);
    mojom::Camera3StreamBufferPtr input_buffer =
        internal::SerializeStreamBuffer(result->input_buffer, streams_,
                                        buffer_handles_);
    if (input_buffer.is_null()) {
      LOGF(ERROR) << "Failed to serialize input stream buffer";
    }
    RemoveReturnBufferLocked(input_buffer->buffer_id, *result->input_buffer);
    r->input_buffer = std::move(input_buffer);
  }

  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    // TODO(lnishan): Handle the errors here.
    std::vector<mojom::Camera3PhyscamMetadataPtr> phys_metadata;
    for (int i = 0; i < result->num_physcam_metadata; ++i) {
      phys_metadata[i] = mojom::Camera3PhyscamMetadata::New();
      int internal_camera_id = 0;
      if (!base::StringToInt(result->physcam_ids[i], &internal_camera_id)) {
        LOGF(ERROR) << "Invalid physical camera ID: " << result->physcam_ids[i];
      }
      int public_camera_id =
          get_public_camera_id_callback_.Run(internal_camera_id);
      if (public_camera_id == -1) {
        LOGF(ERROR) << "Failed to find public camera ID for internal camera "
                    << internal_camera_id;
      }
      phys_metadata[i]->id = public_camera_id;
      phys_metadata[i]->metadata =
          internal::SerializeCameraMetadata(result->physcam_metadata[i]);
    }
    r->physcam_metadata = std::move(phys_metadata);
  }

  return r;
}

mojom::Camera3NotifyMsgPtr CameraDeviceAdapter::PrepareNotifyMsg(
    const camera3_notify_msg_t* msg) {
  // Fill in the data from msg...
  mojom::Camera3NotifyMsgPtr m = mojom::Camera3NotifyMsg::New();
  m->type = static_cast<mojom::Camera3MsgType>(msg->type);

  if (msg->type == CAMERA3_MSG_ERROR) {
    mojom::Camera3ErrorMsgPtr error = mojom::Camera3ErrorMsg::New();
    error->frame_number = msg->message.error.frame_number;
    uint64_t stream_id = 0;
    {
      base::AutoLock l(streams_lock_);
      for (const auto& s : streams_) {
        if (s.second.get() == msg->message.error.error_stream) {
          stream_id = s.first;
          break;
        }
      }
    }
    error->error_stream_id = stream_id;
    error->error_code =
        static_cast<mojom::Camera3ErrorMsgCode>(msg->message.error.error_code);
    m->message = mojom::Camera3NotifyMsgMessage::NewError(std::move(error));
  } else if (msg->type == CAMERA3_MSG_SHUTTER) {
    mojom::Camera3ShutterMsgPtr shutter = mojom::Camera3ShutterMsg::New();
    shutter->frame_number = msg->message.shutter.frame_number;
    shutter->timestamp = msg->message.shutter.timestamp;
    m->message = mojom::Camera3NotifyMsgMessage::NewShutter(std::move(shutter));
  } else {
    LOGF(ERROR) << "Invalid notify message type: " << msg->type;
  }

  return m;
}

void CameraDeviceAdapter::RemoveBufferLocked(
    const camera3_stream_buffer_t& buffer) {
  buffer_handles_lock_.AssertAcquired();
  int release_fence = buffer.release_fence;
  base::ScopedFD scoped_release_fence;
  if (release_fence != -1) {
    release_fence = dup(release_fence);
    if (release_fence == -1) {
      PLOGF(ERROR) << "Failed to dup release_fence";
      return;
    }
    scoped_release_fence.reset(release_fence);
  }

  // Remove the allocated camera buffer handle from |buffer_handles_| and
  // pass it to RemoveBufferOnFenceSyncThread. The buffer handle will be
  // freed after the release fence is signalled.
  const camera_buffer_handle_t* handle =
      camera_buffer_handle_t::FromBufferHandle(*(buffer.buffer));
  if (!handle) {
    return;
  }
  // Remove the buffer handle from |buffer_handles_| now to avoid a race
  // condition where the process_capture_request sends down an existing buffer
  // handle which hasn't been removed in RemoveBufferHandleOnFenceSyncThread.
  uint64_t buffer_id = handle->buffer_id;
  if (buffer_handles_[buffer_id]->state == kRegistered) {
    // Framework registered a new buffer with the same |buffer_id| before we
    // remove the old buffer handle from |buffer_handles_|.
    return;
  }
  std::unique_ptr<camera_buffer_handle_t> buffer_handle;
  buffer_handles_[buffer_id].swap(buffer_handle);
  buffer_handles_.erase(buffer_id);

  {
    base::AutoLock l(fence_sync_thread_lock_);
    if (!fence_sync_thread_.IsRunning()) {
      return;
    }
    fence_sync_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CameraDeviceAdapter::RemoveBufferOnFenceSyncThread,
                       base::Unretained(this), std::move(scoped_release_fence),
                       std::move(buffer_handle)));
  }
}

void CameraDeviceAdapter::RemoveReturnBufferLocked(
    uint64_t buffer_id, const camera3_stream_buffer_t& buffer) {
  buffer_handles_lock_.AssertAcquired();
  DCHECK(buffer_handles_.find(buffer_id) != buffer_handles_.end());
  buffer_handles_[buffer_id]->state = kReturned;
  RemoveBufferLocked(buffer);
}

void CameraDeviceAdapter::CancelBuffersRegistrationLocked(
    const std::vector<std::pair<uint64_t, const camera3_stream_buffer_t&>>&
        registered_buffers) {
  buffer_handles_lock_.AssertAcquired();
  for (const auto& registered_buffer : registered_buffers) {
    RemoveReturnBufferLocked(registered_buffer.first, registered_buffer.second);
  }
}

void CameraDeviceAdapter::RemoveBufferOnFenceSyncThread(
    base::ScopedFD release_fence,
    std::unique_ptr<camera_buffer_handle_t> buffer) {
  // In theory the release fence should be signaled by HAL as soon as possible,
  // and we could just set a large value for the timeout.  The timeout here is
  // set to 3 ms to allow testing multiple fences in round-robin if there are
  // multiple active buffers.
  const int kSyncWaitTimeoutMs = 3;
  const camera_buffer_handle_t* handle = buffer.get();
  DCHECK(handle);

  if (!release_fence.is_valid() ||
      !sync_wait(release_fence.get(), kSyncWaitTimeoutMs)) {
    VLOGF(1) << "Buffer 0x" << std::hex << handle->buffer_id << " removed";
  } else {
    // sync_wait() timeout. Reschedule and try to remove the buffer again.
    VLOGF(2) << "Release fence sync_wait() timeout on buffer 0x" << std::hex
             << handle->buffer_id;
    fence_sync_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CameraDeviceAdapter::RemoveBufferOnFenceSyncThread,
                       base::Unretained(this), std::move(release_fence),
                       std::move(buffer)));
  }
}

void CameraDeviceAdapter::ResetDeviceOpsDelegateOnThread() {
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());
  device_ops_delegate_.reset();
}

void CameraDeviceAdapter::ResetCallbackOpsDelegateOnThread() {
  DCHECK(camera_callback_ops_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(callback_ops_delegate_lock_);
  callback_ops_delegate_.reset();
}

void CameraDeviceAdapter::ForceCloseOnDeviceOpsThread() {
  DCHECK(camera_device_ops_thread_.task_runner()->BelongsToCurrentThread());
  Flush();
  camera3_notify_msg_t msg = {
      .type = CAMERA3_MSG_ERROR,
      .message.error = {.frame_number = 0,
                        .error_stream = nullptr,
                        .error_code = CAMERA3_MSG_ERROR_DEVICE}};
  NotifyClient(this, msg);
  Close();
}

}  // namespace cros
