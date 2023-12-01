// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_device_impl.h"

#include <utility>

#include <base/check.h>
#include <base/numerics/safe_conversions.h>
#include <sync/sync.h>

#include "camera3_test/camera3_perf_log.h"
#include "common/camera_hal3_helpers.h"
#include "cros-camera/common.h"

namespace camera3_test {

static void ExpectKeyValueGreaterThanI64(const camera_metadata_t* settings,
                                         int32_t key,
                                         const char* key_name,
                                         int64_t value) {
  camera_metadata_ro_entry_t entry;
  ASSERT_EQ(0, find_camera_metadata_ro_entry(settings, key, &entry))
      << "Cannot find the metadata " << key_name;
  ASSERT_GT(entry.data.i64[0], value) << "Wrong value of metadata " << key_name;
}
#define EXPECT_KEY_VALUE_GT_I64(settings, key, value) \
  ExpectKeyValueGreaterThanI64(settings, key, #key, value)

Camera3DeviceImpl::Camera3DeviceImpl(int cam_id)
    : cam_id_(cam_id),
      hal_thread_(GetThreadName(cam_id).c_str()),
      initialized_(false),
      cam_stream_idx_(0),
      gralloc_(Camera3TestGralloc::GetInstance()),
      request_frame_number_(kInitialFrameNumber) {
  DETACH_FROM_THREAD(thread_checker_);
}

int Camera3DeviceImpl::Initialize(Camera3Module* cam_module) {
  if (!cam_module || !hal_thread_.Start()) {
    return -EINVAL;
  }
  int result = -EIO;
  hal_thread_.PostTaskSync(
      FROM_HERE, base::BindOnce(&Camera3DeviceImpl::InitializeOnThread,
                                base::Unretained(this), cam_module, &result));
  return result;
}

void Camera3DeviceImpl::Destroy() {
  int result = -EIO;
  hal_thread_.PostTaskSync(FROM_HERE,
                           base::BindOnce(&Camera3DeviceImpl::DestroyOnThread,
                                          base::Unretained(this), &result));
  EXPECT_EQ(0, result) << "Camera device close failed";
  hal_thread_.Stop();

  DETACH_FROM_THREAD(thread_checker_);
}

void Camera3DeviceImpl::RegisterProcessCaptureResultCallback(
    Camera3Device::ProcessCaptureResultCallback cb) {
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &Camera3DeviceImpl::RegisterProcessCaptureResultCallbackOnThread,
          base::Unretained(this), cb));
}

void Camera3DeviceImpl::RegisterNotifyCallback(
    Camera3Device::NotifyCallback cb) {
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::RegisterNotifyCallbackOnThread,
                     base::Unretained(this), cb));
}

void Camera3DeviceImpl::RegisterResultMetadataOutputBufferCallback(
    Camera3Device::ProcessResultMetadataOutputBuffersCallback cb) {
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::
                         RegisterResultMetadataOutputBufferCallbackOnThread,
                     base::Unretained(this), cb));
}

void Camera3DeviceImpl::RegisterPartialMetadataCallback(
    Camera3Device::ProcessPartialMetadataCallback cb) {
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &Camera3DeviceImpl::RegisterPartialMetadataCallbackOnThread,
          base::Unretained(this), cb));
}

bool Camera3DeviceImpl::IsTemplateSupported(int32_t type) {
  bool result = false;
  hal_thread_.PostTaskSync(
      FROM_HERE, base::BindOnce(&Camera3DeviceImpl::IsTemplateSupportedOnThread,
                                base::Unretained(this), type, &result));
  return result;
}

const camera_metadata_t* Camera3DeviceImpl::ConstructDefaultRequestSettings(
    int type) {
  const camera_metadata_t* metadata = nullptr;
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &Camera3DeviceImpl::ConstructDefaultRequestSettingsOnThread,
          base::Unretained(this), type, &metadata));
  return metadata;
}

void Camera3DeviceImpl::AddStream(int format,
                                  int width,
                                  int height,
                                  int crop_rotate_scale_degrees,
                                  camera3_stream_type_t type) {
  hal_thread_.PostTaskSync(
      FROM_HERE, base::BindOnce(&Camera3DeviceImpl::AddStreamOnThread,
                                base::Unretained(this), format, width, height,
                                crop_rotate_scale_degrees, type));
}

int Camera3DeviceImpl::ConfigureStreams(
    std::vector<const camera3_stream_t*>* streams) {
  int32_t result = -EIO;
  hal_thread_.PostTaskSync(
      FROM_HERE, base::BindOnce(&Camera3DeviceImpl::ConfigureStreamsOnThread,
                                base::Unretained(this), streams, &result));
  return result;
}

int Camera3DeviceImpl::AllocateOutputStreamBuffers(
    std::vector<camera3_stream_buffer_t>* output_buffers) {
  int32_t result = -EIO;
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::AllocateOutputStreamBuffersOnThread,
                     base::Unretained(this), output_buffers, &result));
  return result;
}

int Camera3DeviceImpl::AllocateOutputBuffersByStreams(
    const std::vector<const camera3_stream_t*>& streams,
    std::vector<camera3_stream_buffer_t>* output_buffers) {
  int32_t result = -EIO;
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::AllocateOutputBuffersByStreamsOnThread,
                     base::Unretained(this), &streams, output_buffers,
                     &result));
  return result;
}

int Camera3DeviceImpl::RegisterOutputBuffer(
    const camera3_stream_t& stream, cros::ScopedBufferHandle unique_buffer) {
  int32_t result = -EIO;
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::RegisterOutputBufferOnThread,
                     base::Unretained(this), &stream, std::move(unique_buffer),
                     &result));
  return result;
}

int Camera3DeviceImpl::ProcessCaptureRequest(
    camera3_capture_request_t* capture_request) {
  int32_t result = -EIO;
  hal_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::ProcessCaptureRequestOnThread,
                     base::Unretained(this), capture_request, &result));
  return result;
}

int Camera3DeviceImpl::WaitShutter(const struct timespec& timeout) {
  if (!initialized_) {
    return -ENODEV;
  }
  if (!process_capture_result_cb_.is_null()) {
    LOGF(ERROR)
        << "Test has registered its own process_capture_result callback "
           "function and thus must provide its own "
        << __func__;
    return -EINVAL;
  }
  return sem_timedwait(&shutter_sem_, &timeout);
}

int Camera3DeviceImpl::WaitCaptureResult(const struct timespec& timeout) {
  if (!initialized_) {
    return -ENODEV;
  }
  if (!process_capture_result_cb_.is_null()) {
    LOGF(ERROR)
        << "Test has registered its own process_capture_result callback "
           "function and thus must provide its own "
        << __func__;
    return -EINVAL;
  }
  return sem_timedwait(&capture_result_sem_, &timeout);
}

int Camera3DeviceImpl::Flush() {
  DCHECK(dev_connector_);

  return dev_connector_->Flush();
}

void Camera3DeviceImpl::InitializeOnThread(Camera3Module* cam_module,
                                           int* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (initialized_) {
    LOGF(ERROR) << "Device " << cam_id_ << " is already initialized";
    *result = -EINVAL;
    return;
  }
  // Open camera device
  Camera3PerfLog::GetInstance()->UpdateDeviceEvent(
      cam_id_, DeviceEvent::OPENING, base::TimeTicks::Now());
  *result = -ENODEV;
  dev_connector_ = cam_module->OpenDevice(cam_id_);
  if (!dev_connector_) {
    return;
  }

  *result = -EINVAL;
  ASSERT_NE(nullptr, gralloc_) << "Gralloc initialization fails";

  camera_info cam_info;
  ASSERT_EQ(0, cam_module->GetCameraInfo(cam_id_, &cam_info));
  device_api_version_ = cam_info.device_version;
  static_info_.reset(new Camera3Device::StaticInfo(cam_info));
  ASSERT_TRUE(static_info_->IsHardwareLevelAtLeastExternal())
      << "The device must support at least EXTERNAL hardware level";

  // Initialize camera device
  Camera3DeviceImpl::notify = Camera3DeviceImpl::NotifyForwarder;
  Camera3DeviceImpl::process_capture_result =
      Camera3DeviceImpl::ProcessCaptureResultForwarder;
  *result = dev_connector_->Initialize(this, cam_info.device_version);
  if (*result) {
    return;
  }
  Camera3PerfLog::GetInstance()->UpdateDeviceEvent(cam_id_, DeviceEvent::OPENED,
                                                   base::TimeTicks::Now());

  sem_init(&shutter_sem_, 0, 0);
  sem_init(&capture_result_sem_, 0, 0);
  initialized_ = true;
}

void Camera3DeviceImpl::RegisterProcessCaptureResultCallbackOnThread(
    Camera3Device::ProcessCaptureResultCallback cb) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  process_capture_result_cb_ = cb;
}

void Camera3DeviceImpl::RegisterNotifyCallbackOnThread(
    Camera3Device::NotifyCallback cb) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  notify_cb_ = cb;
}

void Camera3DeviceImpl::RegisterResultMetadataOutputBufferCallbackOnThread(
    Camera3Device::ProcessResultMetadataOutputBuffersCallback cb) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  process_result_metadata_output_buffers_cb_ = cb;
}

void Camera3DeviceImpl::RegisterPartialMetadataCallbackOnThread(
    Camera3Device::ProcessPartialMetadataCallback cb) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  process_partial_metadata_cb_ = cb;
}

void Camera3DeviceImpl::IsTemplateSupportedOnThread(int32_t type,
                                                    bool* result) {
  if (initialized_) {
    *result =
        (type != CAMERA3_TEMPLATE_MANUAL ||
         static_info_->IsCapabilitySupported(
             ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR)) &&
        (type != CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG ||
         static_info_->IsCapabilitySupported(
             ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING));
  }
}

void Camera3DeviceImpl::ConstructDefaultRequestSettingsOnThread(
    int type, const camera_metadata_t** result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (initialized_) {
    *result = dev_connector_->ConstructDefaultRequestSettings(type);
  }
}

void Camera3DeviceImpl::AddStreamOnThread(int format,
                                          int width,
                                          int height,
                                          int crop_rotate_scale_degrees,
                                          camera3_stream_type_t type) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (initialized_) {
    auto& cur_stream = cam_stream_[!cam_stream_idx_];
    // Push to the bin that is not used currently
    cros::internal::camera3_stream_aux_t stream = {};
    stream.stream_type = type;
    stream.width = width;
    stream.height = height;
    stream.format = format;
    if (type == CAMERA3_STREAM_OUTPUT &&
        format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) {
      // This is a preview stream. Add the usage flag for preview.
      stream.usage |= GRALLOC_USAGE_HW_COMPOSER;
    }
    if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
      stream.physical_camera_id = "";
    }
    stream.crop_rotate_scale_degrees = crop_rotate_scale_degrees;
    cur_stream.push_back(stream);
  }
}

void Camera3DeviceImpl::ConfigureStreamsOnThread(
    std::vector<const camera3_stream_t*>* streams, int* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  *result = -EINVAL;
  if (!initialized_) {
    *result = -ENODEV;
    return;
  }

  // Check whether there are streams
  if (cam_stream_[!cam_stream_idx_].size() == 0) {
    return;
  }

  // Prepare stream configuration
  std::vector<camera3_stream_t*> cam_streams;
  camera3_stream_configuration_t cam_stream_config = {};
  for (size_t i = 0; i < cam_stream_[!cam_stream_idx_].size(); i++) {
    cam_streams.push_back(&cam_stream_[!cam_stream_idx_][i]);
  }
  cam_stream_config.num_streams = cam_streams.size();
  cam_stream_config.streams = cam_streams.data();
  cam_stream_config.operation_mode = CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE;
  if (device_api_version_ >= CAMERA_DEVICE_API_VERSION_3_5) {
    cam_stream_config.session_parameters = nullptr;
  }

  // Configure streams now
  *result = dev_connector_->ConfigureStreams(&cam_stream_config);
  if (*result == 0) {
    for (const auto& it : cam_stream_[!cam_stream_idx_]) {
      if (it.max_buffers == 0) {
        LOGF(ERROR) << "Max number of buffers equal to zero is invalid";
        *result = -EINVAL;
        return;
      }
    }
  }

  // Swap to the other bin
  cam_stream_[cam_stream_idx_].clear();
  cam_stream_idx_ = !cam_stream_idx_;

  if (*result == 0 && streams) {
    streams->clear();
    for (auto const& it : cam_stream_[cam_stream_idx_]) {
      streams->push_back(&it);
    }
  }
}

void Camera3DeviceImpl::AllocateOutputStreamBuffersOnThread(
    std::vector<camera3_stream_buffer_t>* output_buffers, int32_t* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  std::vector<const camera3_stream_t*> streams;
  for (const auto& it : cam_stream_[cam_stream_idx_]) {
    if (it.stream_type == CAMERA3_STREAM_OUTPUT ||
        it.stream_type == CAMERA3_STREAM_BIDIRECTIONAL) {
      streams.push_back(&it);
    }
  }
  AllocateOutputBuffersByStreamsOnThread(&streams, output_buffers, result);
}

void Camera3DeviceImpl::AllocateOutputBuffersByStreamsOnThread(
    const std::vector<const camera3_stream_t*>* streams,
    std::vector<camera3_stream_buffer_t>* output_buffers,
    int32_t* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  *result = -EINVAL;
  if (!initialized_) {
    *result = -ENODEV;
    return;
  }

  if (!output_buffers || streams->empty()) {
    return;
  }
  int32_t jpeg_max_size = 0;
  if (std::find_if(streams->begin(), streams->end(),
                   [](const camera3_stream_t* stream) {
                     return stream->format == HAL_PIXEL_FORMAT_BLOB;
                   }) != streams->end()) {
    jpeg_max_size = static_info_->GetJpegMaxSize();
    if (jpeg_max_size <= 0) {
      return;
    }
  }

  for (const auto& it : *streams) {
    cros::ScopedBufferHandle buffer = gralloc_->Allocate(
        (it->format == HAL_PIXEL_FORMAT_BLOB) ? jpeg_max_size : it->width,
        (it->format == HAL_PIXEL_FORMAT_BLOB) ? 1 : it->height, it->format,
        it->usage);
    if (!buffer) {
      LOGF(ERROR) << "Gralloc allocation fails";
      *result = -ENOMEM;
      return;
    }

    camera3_stream_buffer_t stream_buffer;
    camera3_stream_t* stream = const_cast<camera3_stream_t*>(it);

    stream_buffer = {.stream = stream,
                     .buffer = buffer.get(),
                     .status = CAMERA3_BUFFER_STATUS_OK,
                     .acquire_fence = -1,
                     .release_fence = -1};
    stream_buffer_map_[stream].push_back(std::move(buffer));
    output_buffers->push_back(stream_buffer);
  }
  *result = 0;
}

void Camera3DeviceImpl::RegisterOutputBufferOnThread(
    const camera3_stream_t* stream,
    cros::ScopedBufferHandle unique_buffer,
    int32_t* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!initialized_) {
    *result = -ENODEV;
    return;
  }
  if (!unique_buffer) {
    *result = -EINVAL;
    return;
  }
  stream_buffer_map_[stream].emplace_back(std::move(unique_buffer));
  *result = 0;
}

void Camera3DeviceImpl::ProcessCaptureRequestOnThread(
    camera3_capture_request_t* request, int* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!initialized_) {
    *result = -ENODEV;
    return;
  }
  if (request) {
    capture_request_map_[request_frame_number_] = *request;
    capture_request_map_[request_frame_number_].frame_number =
        request_frame_number_;
    for (uint32_t i = 0; i < request->num_output_buffers; i++) {
      stream_output_buffer_map_[request->output_buffers[i].stream].push_back(
          *request->output_buffers[i].buffer);
    }
  }
  *result = dev_connector_->ProcessCaptureRequest(
      request ? &capture_request_map_[request_frame_number_] : request);
  if (*result == 0) {
    request->frame_number = request_frame_number_;
    request_frame_number_++;
  }
}

Camera3DeviceImpl::StreamBuffer::StreamBuffer(
    const camera3_stream_buffer_t& stream_buffer)
    : camera3_stream_buffer_t(stream_buffer) {
  buffer_handle = *stream_buffer.buffer;
}

Camera3DeviceImpl::CaptureResult::CaptureResult(
    const camera3_capture_result_t& result)
    : camera3_capture_result_t(result) {
  if (result.result) {
    metadata_result.reset(clone_camera_metadata(result.result));
  }
  for (uint32_t i = 0; i < result.num_output_buffers; i++) {
    stream_buffers.emplace_back(result.output_buffers[i]);
  }
}

void Camera3DeviceImpl::ProcessCaptureResultOnThread(
    std::unique_ptr<CaptureResult> result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  ASSERT_NE(nullptr, result) << "Capture result is null";
  // At least one of metadata or output buffers or input buffer should be
  // returned
  ASSERT_TRUE((result->metadata_result != nullptr) ||
              (result->num_output_buffers != 0) ||
              (result->input_buffer != NULL))
      << "No result data provided by HAL for frame " << result->frame_number;
  if (result->num_output_buffers) {
    ASSERT_NE(nullptr, result->output_buffers)
        << "No output buffer is returned while " << result->num_output_buffers
        << " are expected";
  }
  ASSERT_NE(capture_request_map_.end(),
            capture_request_map_.find(result->frame_number))
      << "A result is received for nonexistent request (frame number "
      << result->frame_number << ")";

  // For HAL3.2 or above, If HAL doesn't support partial, it must always set
  // partial_result to 1 when metadata is included in this result.
  ASSERT_TRUE(UsePartialResult() || !result->metadata_result ||
              result->partial_result == 1)
      << "Result is malformed: partial_result must be 1 if partial result is "
         "not supported";
  // If partial_result > 0, there should be metadata returned in this result;
  // otherwise, there should be none.
  ASSERT_TRUE((result->partial_result > 0) ==
              (result->metadata_result != nullptr));

  if (result->metadata_result) {
    ProcessPartialResult(result.get());
  }

  for (auto& stream_buffer : result->stream_buffers) {
    ASSERT_NE(nullptr, stream_buffer.buffer)
        << "Capture result output buffer is null";
    // An error may be expected while flushing
    EXPECT_EQ(CAMERA3_BUFFER_STATUS_OK, stream_buffer.status)
        << "Capture result buffer status error";
    ASSERT_EQ(-1, stream_buffer.acquire_fence)
        << "Capture result buffer fence error";

    // Check buffers for a given streams are returned in order
    ASSERT_FALSE(stream_output_buffer_map_[stream_buffer.stream].empty());
    ASSERT_EQ(stream_output_buffer_map_[stream_buffer.stream].front(),
              stream_buffer.buffer_handle)
        << "Buffers of the same stream are delivered out of order";
    stream_output_buffer_map_[stream_buffer.stream].pop_front();
    ASSERT_TRUE(cros::WaitOnAndClearReleaseFence(stream_buffer, 1000))
        << "Error waiting on buffer acquire fence";
  }
  capture_result_info_map_[result->frame_number].output_buffers_.insert(
      capture_result_info_map_[result->frame_number].output_buffers_.end(),
      result->stream_buffers.begin(), result->stream_buffers.end());

  capture_result_info_map_[result->frame_number].num_output_buffers_ +=
      result->num_output_buffers;
  if (result->input_buffer != nullptr) {
    capture_result_info_map_[result->frame_number].have_input_buffer_ = true;
  }
  ASSERT_LE(capture_result_info_map_[result->frame_number].num_output_buffers_,
            capture_request_map_[result->frame_number].num_output_buffers);
  if (capture_result_info_map_[result->frame_number].num_output_buffers_ ==
          capture_request_map_[result->frame_number].num_output_buffers &&
      capture_result_info_map_[result->frame_number].have_input_buffer_ ==
          (capture_request_map_[result->frame_number].input_buffer !=
           nullptr) &&
      capture_result_info_map_[result->frame_number].have_result_metadata_) {
    ASSERT_EQ(completed_request_set_.end(),
              completed_request_set_.find(result->frame_number))
        << "Multiple results are received for the same request";
    completed_request_set_.insert(result->frame_number);

    // Process all received metadata and output buffers
    std::vector<cros::ScopedBufferHandle> unique_buffers;
    if (GetOutputStreamBufferHandles(
            capture_result_info_map_[result->frame_number].output_buffers_,
            &unique_buffers)) {
      ADD_FAILURE() << "Failed to get output buffers";
    }
    ScopedCameraMetadata final_metadata(
        capture_result_info_map_[result->frame_number].MergePartialMetadata());
    EXPECT_KEY_VALUE_GT_I64(final_metadata.get(), ANDROID_SENSOR_TIMESTAMP, 0);
    if (!process_result_metadata_output_buffers_cb_.is_null()) {
      process_result_metadata_output_buffers_cb_.Run(result->frame_number,
                                                     std::move(final_metadata),
                                                     std::move(unique_buffers));
    }
    std::vector<ScopedCameraMetadata> partial_metadata;
    partial_metadata.swap(
        capture_result_info_map_[result->frame_number].partial_metadata_);
    if (!process_partial_metadata_cb_.is_null()) {
      process_partial_metadata_cb_.Run(&partial_metadata);
    }

    capture_request_map_.erase(result->frame_number);
    capture_result_info_map_.erase(result->frame_number);

    // Everything looks fine. Post it now.
    sem_post(&capture_result_sem_);
  }
}

void Camera3DeviceImpl::NotifyOnThread(camera3_notify_msg_t msg) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  EXPECT_EQ(CAMERA3_MSG_SHUTTER, msg.type)
      << "Shutter error = " << msg.message.error.error_code;

  // Use the timestamp reported from camera instead of base::TimeTicks::Now()
  // since HAL may not notify() shutter messages in time.
  const int64_t timestamp_ns =
      base::checked_cast<int64_t>(msg.message.shutter.timestamp / 1000LL);
  Camera3PerfLog::GetInstance()->UpdateFrameEvent(
      cam_id_, msg.message.shutter.frame_number, FrameEvent::SHUTTER,
      base::TimeTicks() + base::Microseconds(timestamp_ns));

  if (msg.type == CAMERA3_MSG_SHUTTER) {
    sem_post(&shutter_sem_);
  }
}

void Camera3DeviceImpl::DestroyOnThread(int* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  *result = -EINVAL;
  if (!initialized_) {
    *result = -ENODEV;
    return;
  }

  dev_connector_.reset();

  sem_destroy(&shutter_sem_);
  sem_destroy(&capture_result_sem_);
  initialized_ = false;
  *result = 0;
}

const Camera3Device::StaticInfo* Camera3DeviceImpl::GetStaticInfo() const {
  return static_info_.get();
}

void Camera3DeviceImpl::ProcessCaptureResultForwarder(
    const camera3_callback_ops* cb, const camera3_capture_result_t* result) {
  // Forward to callback of instance
  Camera3DeviceImpl* d =
      const_cast<Camera3DeviceImpl*>(static_cast<const Camera3DeviceImpl*>(cb));
  d->ProcessCaptureResult(result);
}

void Camera3DeviceImpl::NotifyForwarder(const camera3_callback_ops* cb,
                                        const camera3_notify_msg_t* msg) {
  // Forward to callback of instance
  Camera3DeviceImpl* d =
      const_cast<Camera3DeviceImpl*>(static_cast<const Camera3DeviceImpl*>(cb));
  d->Notify(msg);
}

void Camera3DeviceImpl::ProcessCaptureResult(
    const camera3_capture_result_t* result) {
  if (!process_capture_result_cb_.is_null()) {
    process_capture_result_cb_.Run(result);
    return;
  }
  std::unique_ptr<CaptureResult> unique_result(new CaptureResult(*result));
  hal_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(&Camera3DeviceImpl::ProcessCaptureResultOnThread,
                     base::Unretained(this), std::move(unique_result)));
}

void Camera3DeviceImpl::Notify(const camera3_notify_msg_t* msg) {
  if (!notify_cb_.is_null()) {
    notify_cb_.Run(msg);
    return;
  }
  hal_thread_.PostTaskAsync(FROM_HERE,
                            base::BindOnce(&Camera3DeviceImpl::NotifyOnThread,
                                           base::Unretained(this), *msg));
}

int Camera3DeviceImpl::GetOutputStreamBufferHandles(
    const std::vector<StreamBuffer>& output_buffers,
    std::vector<cros::ScopedBufferHandle>* unique_buffers) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  for (const auto& output_buffer : output_buffers) {
    if (!output_buffer.buffer ||
        stream_buffer_map_.find(output_buffer.stream) ==
            stream_buffer_map_.end()) {
      LOGF(ERROR) << "Failed to find configured stream or buffer is invalid";
      return -EINVAL;
    }

    auto stream_buffers = &stream_buffer_map_[output_buffer.stream];
    auto it = std::find_if(stream_buffers->begin(), stream_buffers->end(),
                           [=](const cros::ScopedBufferHandle& buffer) {
                             return *buffer == output_buffer.buffer_handle;
                           });
    if (it != stream_buffers->end()) {
      unique_buffers->push_back(std::move(*it));
      stream_buffers->erase(it);
    } else {
      LOGF(ERROR) << "Failed to find output buffer";
      return -EINVAL;
    }
  }
  return 0;
}

bool Camera3DeviceImpl::UsePartialResult() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return static_info_->GetPartialResultCount() > 1;
}

void Camera3DeviceImpl::ProcessPartialResult(CaptureResult* result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // True if this partial result is the final one. If HAL does not use partial
  // result, the value is True by default.
  bool is_final_partial_result = !UsePartialResult();
  // Check if this result carries only partial metadata
  if (UsePartialResult() && result->metadata_result != nullptr) {
    EXPECT_LE(result->partial_result, static_info_->GetPartialResultCount());
    EXPECT_GE(result->partial_result, 1);
    is_final_partial_result =
        (result->partial_result == static_info_->GetPartialResultCount());
  }

  // Did we get the (final) result metadata for this capture?
  if (result->metadata_result != nullptr && is_final_partial_result) {
    EXPECT_FALSE(
        capture_result_info_map_[result->frame_number].have_result_metadata_)
        << "Called multiple times with final metadata";
    capture_result_info_map_[result->frame_number].have_result_metadata_ = true;
  }

  capture_result_info_map_[result->frame_number].partial_metadata_.push_back(
      std::move(result->metadata_result));
}

Camera3DeviceImpl::CaptureResultInfo::CaptureResultInfo()
    : have_input_buffer_(false),
      num_output_buffers_(0),
      have_result_metadata_(false) {
  DETACH_FROM_THREAD(thread_checker_);
}

bool Camera3DeviceImpl::CaptureResultInfo::IsMetadataKeyAvailable(
    int32_t key) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return GetMetadataKeyEntry(key, nullptr);
}

int32_t Camera3DeviceImpl::CaptureResultInfo::GetMetadataKeyValue(
    int32_t key) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  camera_metadata_ro_entry_t entry;
  return GetMetadataKeyEntry(key, &entry) ? entry.data.i32[0] : -EINVAL;
}

int64_t Camera3DeviceImpl::CaptureResultInfo::GetMetadataKeyValue64(
    int32_t key) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  camera_metadata_ro_entry_t entry;
  return GetMetadataKeyEntry(key, &entry) ? entry.data.i64[0] : -EINVAL;
}

ScopedCameraMetadata
Camera3DeviceImpl::CaptureResultInfo::MergePartialMetadata() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  size_t entry_count = 0;
  size_t data_count = 0;
  for (const auto& it : partial_metadata_) {
    entry_count += get_camera_metadata_entry_count(it.get());
    data_count += get_camera_metadata_data_count(it.get());
  }
  camera_metadata_t* metadata =
      allocate_camera_metadata(entry_count, data_count);
  if (!metadata) {
    ADD_FAILURE() << "Can't allocate larger metadata buffer";
    return nullptr;
  }
  for (const auto& it : partial_metadata_) {
    append_camera_metadata(metadata, it.get());
  }
  return ScopedCameraMetadata(metadata);
}

bool Camera3DeviceImpl::CaptureResultInfo::GetMetadataKeyEntry(
    int32_t key, camera_metadata_ro_entry_t* entry) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  camera_metadata_ro_entry_t local_entry;
  entry = entry ? entry : &local_entry;
  for (const auto& it : partial_metadata_) {
    if (find_camera_metadata_ro_entry(it.get(), key, entry) == 0) {
      return true;
    }
  }
  return false;
}

const std::string Camera3DeviceImpl::GetThreadName(int cam_id) {
  const size_t kThreadNameLength = 30;
  char thread_name[kThreadNameLength];
  snprintf(thread_name, kThreadNameLength, "Camera3 Test Device %d Thread",
           cam_id);
  return std::string(thread_name);
}

}  // namespace camera3_test
