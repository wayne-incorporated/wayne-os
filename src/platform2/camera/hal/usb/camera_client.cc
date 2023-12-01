/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/camera_client.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/posix/safe_strerror.h>
#include <base/threading/platform_thread.h>
#include <sync/sync.h>
#include <system/camera_metadata.h>

#include "cros-camera/common.h"
#include "cros-camera/utils/camera_config.h"
#include "hal/usb/cached_frame.h"
#include "hal/usb/camera_hal.h"
#include "hal/usb/camera_hal_device_ops.h"
#include "hal/usb/quirks.h"
#include "hal/usb/stream_format.h"
#include "hal/usb/tracing.h"

namespace cros {

namespace {

const int kBufferFenceReady = -1;

// We need to compare the aspect ratio from native sensor resolution.
// The native resolution may not be just the size. It may be a little larger.
// Add a margin to check if the sensor aspect ratio fall in the specific aspect
// ratio.
// 16:9=1.778, 16:10=1.6, 3:2=1.5, 4:3=1.333
const float kAspectRatioMargin = 0.04;

// Chrome and camera service uses GRALLOC_USAGE_PRIVATE_1 to indicate still
// capture YUV buffers.
constexpr uint32_t GRALLOC_USAGE_STILL_CAPTURE = GRALLOC_USAGE_PRIVATE_1;

// Resolves to a supported frame rate within the given target fps range in
// |metadata|. If it fails, try the one that is closest to the target range.
// If there are two candidates, choose the larger one.
int ResolvedFrameRateFromMetadata(const android::CameraMetadata& metadata,
                                  const SupportedFormats& qualified_formats,
                                  const Size& resolution,
                                  const int& device_id) {
  DCHECK(metadata.exists(ANDROID_CONTROL_AE_TARGET_FPS_RANGE));

  int resolved_fps = 0;

  const SupportedFormat* format = FindFormatByResolution(
      qualified_formats, resolution.width, resolution.height);
  if (format == nullptr) {
    LOGFID(ERROR, device_id)
        << "Cannot find resolution in supported list: width "
        << resolution.width << ", height " << resolution.height;
    return resolved_fps;
  }

  camera_metadata_ro_entry entry =
      metadata.find(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);
  const int target_min_fps = entry.data.i32[0];
  const int target_max_fps = entry.data.i32[1];
  int min_diff = std::numeric_limits<int>::max();
  for (const float& frame_rate : format->frame_rates) {
    int fps = std::round(frame_rate);
    int diff_to_max = std::max(0, fps - target_max_fps);
    int diff_to_min = std::max(0, target_min_fps - fps);
    int diff = diff_to_max > 0 ? diff_to_max : diff_to_min;
    if (diff < min_diff || (diff == min_diff && fps > resolved_fps)) {
      resolved_fps = fps;
      min_diff = diff;
    }
  }
  if (min_diff > 0) {
    LOGFID_THROTTLED(WARNING, device_id, 60)
        << "Cannot resolve to a valid frame rate within the target range ("
        << target_min_fps << ", " << target_max_fps
        << "). Resolved to:  " << resolved_fps;
  }
  return resolved_fps;
}

}  // namespace

CameraClient::CameraClient(
    int id,
    const DeviceInfo& device_info,
    const camera_metadata_t& static_metadata,
    const camera_metadata_t& request_template,
    const hw_module_t* module,
    hw_device_t** hw_device,
    CameraPrivacySwitchMonitor* hw_privacy_switch_monitor,
    ClientType client_type,
    bool sw_privacy_switch_on)
    : id_(id),
      device_info_(device_info),
      static_metadata_(clone_camera_metadata(&static_metadata)),
      device_(new V4L2CameraDevice(
          device_info, hw_privacy_switch_monitor, sw_privacy_switch_on)),
      callback_ops_(nullptr),
      sw_privacy_switch_on_(sw_privacy_switch_on),
      request_thread_("Capture request thread"),
      camera_metrics_(CameraMetrics::New()) {
  memset(&camera3_device_, 0, sizeof(camera3_device_));
  camera3_device_.common.tag = HARDWARE_DEVICE_TAG;
  camera3_device_.common.version = CAMERA_DEVICE_API_VERSION_3_5;
  camera3_device_.common.close = cros::camera_device_close;
  camera3_device_.common.module = const_cast<hw_module_t*>(module);
  camera3_device_.ops = &g_camera_device_ops;
  camera3_device_.priv = this;
  *hw_device = &camera3_device_.common;

  ops_thread_checker_.DetachFromThread();

  SupportedFormats supported_formats =
      device_->GetDeviceSupportedFormats(device_info_.device_path);
  qualified_formats_ =
      GetQualifiedFormats(supported_formats, device_info_.quirks);

  metadata_handler_ = std::make_unique<MetadataHandler>(
      static_metadata, request_template, device_info, device_.get(),
      qualified_formats_);

  std::unique_ptr<CameraConfig> camera_config =
      CameraConfig::Create(constants::kCrosCameraConfigPathString);
  if (client_type == ClientType::kAndroid) {
    max_stream_width_ = camera_config->GetInteger(
        constants::kCrosUsbAndroidMaxStreamWidth,
        camera_config->GetInteger(constants::kCrosUsbMaxStreamWidth,
                                  std::numeric_limits<int>::max()));

    max_stream_height_ = camera_config->GetInteger(
        constants::kCrosUsbAndroidMaxStreamHeight,
        camera_config->GetInteger(constants::kCrosUsbMaxStreamHeight,
                                  std::numeric_limits<int>::max()));
  } else {
    max_stream_width_ = camera_config->GetInteger(
        constants::kCrosUsbMaxStreamWidth, std::numeric_limits<int>::max());
    max_stream_height_ = camera_config->GetInteger(
        constants::kCrosUsbMaxStreamHeight, std::numeric_limits<int>::max());
  }
  jda_resolution_cap_ =
      Size(camera_config->GetInteger(constants::kCrosUsbJDACapWidth,
                                     std::numeric_limits<int>::max()),
           camera_config->GetInteger(constants::kCrosUsbJDACapHeight,
                                     std::numeric_limits<int>::max()));
}

CameraClient::~CameraClient() {}

int CameraClient::OpenDevice() {
  VLOGFID(1, id_);
  DCHECK(thread_checker_.CalledOnValidThread());

  int ret = device_->Connect(device_info_.device_path);
  if (ret) {
    LOGFID(ERROR, id_) << "Connect failed: " << base::safe_strerror(-ret);
    return ret;
  }

  return 0;
}

int CameraClient::CloseDevice() {
  VLOGFID(1, id_);
  DCHECK(ops_thread_checker_.CalledOnValidThread());

  if (device_info_.enable_face_detection) {
    if (request_handler_) {
      camera_metrics_->SendFaceAeMaxDetectedFaces(
          request_handler_->GetMaxNumDetectedFaces());
    }
  }
  StreamOff();
  device_->Disconnect();
  return 0;
}

void CameraClient::SetPrivacySwitchState(bool on) {
  if (sw_privacy_switch_on_ == on) {
    return;
  }
  sw_privacy_switch_on_ = on;
  if (request_handler_) {
    request_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&CameraClient::RequestHandler::SetPrivacySwitchState,
                       base::Unretained(request_handler_.get()), on));
  } else {
    // While not streaming, directly set the state to |device_|.
    device_->SetPrivacySwitchState(on);
  }
}

int CameraClient::Initialize(const camera3_callback_ops_t* callback_ops) {
  VLOGFID(1, id_);
  DCHECK(ops_thread_checker_.CalledOnValidThread());

  callback_ops_ = callback_ops;
  return 0;
}

int CameraClient::ConfigureStreams(
    camera3_stream_configuration_t* stream_config) {
  VLOGFID(1, id_);
  DCHECK(ops_thread_checker_.CalledOnValidThread());
  /* TODO(henryhsu):
   * 1. Remove all pending requests. Post a task to request thread and wait for
   *    the task to be run.
   */
  if (callback_ops_ == nullptr) {
    LOGFID(ERROR, id_) << "Device is not initialized";
    return -EINVAL;
  }

  if (stream_config == nullptr) {
    LOGFID(ERROR, id_) << "NULL stream configuration array";
    return -EINVAL;
  }
  if (stream_config->num_streams == 0) {
    LOGFID(ERROR, id_) << "Empty stream configuration array";
    return -EINVAL;
  }
  if (stream_config->operation_mode !=
      CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE) {
    LOGFID(ERROR, id_) << "Unsupported operation mode: "
                       << stream_config->operation_mode;
    return -EINVAL;
  }

  std::vector<camera3_stream_t*> streams;
  auto streamon_params = BuildStreamOnParameters(stream_config, streams);

  if (!streamon_params.has_value()) {
    return streamon_params.error();
  }

  if (!IsValidStreamSet(streams)) {
    LOGFID(ERROR, id_) << "Invalid stream set";
    return -EINVAL;
  }

  auto ret = StreamOn(streamon_params.value());
  if (!ret.has_value()) {
    LOGFID(ERROR, id_) << "StreamOn failed";
    StreamOff();
    return ret.error();
  }
  SetUpStreams(ret.value(), &streams);

  return 0;
}

const camera_metadata_t* CameraClient::ConstructDefaultRequestSettings(
    int type) {
  VLOGFID(1, id_) << "type=" << type;

  return metadata_handler_->GetDefaultRequestSettings(type);
}

int CameraClient::ProcessCaptureRequest(camera3_capture_request_t* request) {
  VLOGFID(1, id_);
  DCHECK(ops_thread_checker_.CalledOnValidThread());

  if (!request_handler_.get()) {
    LOGFID(INFO, id_) << "Request handler has stopped; ignoring request";
    return -ENODEV;
  }

  if (request == nullptr) {
    LOGFID(ERROR, id_) << "NULL request received";
    return -EINVAL;
  }

  VLOGFID(1, id_) << "Request Frame:" << request->frame_number
                  << ", settings:" << request->settings;

  if (request->input_buffer != nullptr) {
    LOGFID(ERROR, id_) << "Input buffer is not supported";
    return -EINVAL;
  }

  if (request->num_output_buffers <= 0) {
    LOGFID(ERROR, id_) << "Invalid number of output buffers: "
                       << request->num_output_buffers;
    return -EINVAL;
  }

  if (request->settings) {
    latest_request_metadata_ = request->settings;
    if (VLOG_IS_ON(2)) {
      dump_camera_metadata(request->settings, 1, 1);
    }
  }

  for (size_t i = 0; i < request->num_output_buffers; i++) {
    const camera3_stream_buffer_t* buffer = &request->output_buffers[i];
    if (!IsFormatSupported(qualified_formats_, *(buffer->stream))) {
      LOGF(ERROR) << "Unsupported stream parameters. Width: "
                  << buffer->stream->width
                  << ", height: " << buffer->stream->height
                  << ", format: " << buffer->stream->format;
      return -EINVAL;
    }
  }

  // We cannot use |request| after this function returns. So we have to copy
  // necessary information out to |capture_request|. If |request->settings|
  // doesn't exist, use previous metadata.
  std::unique_ptr<CaptureRequest> capture_request(
      new CaptureRequest(*request, latest_request_metadata_));
  request_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraClient::RequestHandler::HandleRequest,
                                base::Unretained(request_handler_.get()),
                                std::move(capture_request)));
  return 0;
}

void CameraClient::Dump(int fd) {
  VLOGFID(1, id_);
}

int CameraClient::Flush(const camera3_device_t* dev) {
  VLOGFID(1, id_);

  // Do nothing if stream is off.
  if (!request_handler_.get()) {
    return 0;
  }

  auto future = cros::Future<int>::Create(nullptr);
  request_handler_->HandleFlush(cros::GetFutureCallback(future));
  future->Get();
  return 0;
}

bool CameraClient::IsValidStreamSet(
    const std::vector<camera3_stream_t*>& streams) {
  DCHECK(ops_thread_checker_.CalledOnValidThread());
  int num_input = 0, num_output = 0;

  // Validate there is no input stream and at least one output stream.
  for (const auto& stream : streams) {
    // A stream may be both input and output (bidirectional).
    if (stream->stream_type == CAMERA3_STREAM_INPUT ||
        stream->stream_type == CAMERA3_STREAM_BIDIRECTIONAL)
      num_input++;
    if (stream->stream_type == CAMERA3_STREAM_OUTPUT ||
        stream->stream_type == CAMERA3_STREAM_BIDIRECTIONAL)
      num_output++;

    if (stream->rotation != CAMERA3_STREAM_ROTATION_0) {
      LOGFID(ERROR, id_) << "Unsupported rotation " << stream->rotation;
      return false;
    }
  }
  VLOGFID(1, id_) << "Configuring " << num_output << " output streams and "
                  << num_input << " input streams";

  if (num_output < 1) {
    LOGFID(ERROR, id_) << "Stream config must have >= 1 output";
    return false;
  }
  if (num_input > 0) {
    LOGFID(ERROR, id_) << "Input Stream is not supported. Number: "
                       << num_input;
    return false;
  }
  return true;
}

void CameraClient::SetUpStreams(int num_buffers,
                                std::vector<camera3_stream_t*>* streams) {
  for (auto& stream : *streams) {
    if (stream->stream_type == CAMERA3_STREAM_OUTPUT ||
        stream->stream_type == CAMERA3_STREAM_BIDIRECTIONAL) {
      stream->usage |=
          GRALLOC_USAGE_SW_WRITE_OFTEN | GRALLOC_USAGE_HW_CAMERA_WRITE;
    }
    if (stream->stream_type == CAMERA3_STREAM_INPUT ||
        stream->stream_type == CAMERA3_STREAM_BIDIRECTIONAL)
      stream->usage |= GRALLOC_USAGE_SW_READ_OFTEN;
    stream->max_buffers = num_buffers;
  }
}

base::expected<CameraClient::StreamOnParameters, CameraClient::Error>
CameraClient::BuildStreamOnParameters(
    const camera3_stream_configuration_t* stream_config,
    std::vector<camera3_stream_t*>& streams) {
  VLOGFID(1, id_) << "Number of Streams: " << stream_config->num_streams;

  StreamOnParameters streamon_params;
  android::CameraMetadata session_params_metadata(
      clone_camera_metadata(stream_config->session_parameters));

  for (size_t i = 0; i < stream_config->num_streams; i++) {
    VLOGFID(1, id_) << "Stream[" << i
                    << "] type=" << stream_config->streams[i]->stream_type
                    << " width=" << stream_config->streams[i]->width
                    << " height=" << stream_config->streams[i]->height
                    << " rotation=" << stream_config->streams[i]->rotation
                    << " degrees="
                    << stream_config->streams[i]->crop_rotate_scale_degrees
                    << " format=0x" << std::hex
                    << stream_config->streams[i]->format << std::dec;

    if (!IsFormatSupported(qualified_formats_, *(stream_config->streams[i]))) {
      LOGF(ERROR) << "Unsupported stream parameters. Width: "
                  << stream_config->streams[i]->width
                  << ", height: " << stream_config->streams[i]->height
                  << ", format: " << stream_config->streams[i]->format;
      return base::unexpected(-EINVAL);
    }
    streams.push_back(stream_config->streams[i]);
    if (i && stream_config->streams[i]->crop_rotate_scale_degrees !=
                 stream_config->streams[i - 1]->crop_rotate_scale_degrees) {
      LOGF(ERROR) << "Unsupported different crop ratate scale degrees";
      return base::unexpected(-EINVAL);
    }
    // Here assume the attribute of all streams are the same.
    switch (stream_config->streams[i]->crop_rotate_scale_degrees) {
      case CAMERA3_STREAM_ROTATION_0:
        streamon_params.crop_rotate_scale_degrees = 0;
        break;
      case CAMERA3_STREAM_ROTATION_90:
        streamon_params.crop_rotate_scale_degrees = 90;
        break;
      case CAMERA3_STREAM_ROTATION_270:
        streamon_params.crop_rotate_scale_degrees = 270;
        break;
      default:
        LOGF(ERROR) << "Unrecognized crop_rotate_scale_degrees: "
                    << stream_config->streams[i]->crop_rotate_scale_degrees;
        return base::unexpected(-EINVAL);
    }

    // Skip BLOB format to avoid to use too large resolution as preview size,
    // unless we prefer large preview for the camera and JDA is capable of the
    // resolution.
    const bool try_blob =
        device_info_.quirks & kQuirkPreferLargePreviewResolution;
    const bool is_jda_capable =
        stream_config->streams[i]->width <= jda_resolution_cap_.width &&
        stream_config->streams[i]->height <= jda_resolution_cap_.height;
    if (!(try_blob && is_jda_capable) &&
        stream_config->streams[i]->format == HAL_PIXEL_FORMAT_BLOB &&
        stream_config->num_streams > 1) {
      continue;
    }

    const Size resolution(stream_config->streams[i]->width,
                          stream_config->streams[i]->height);
    int frame_rate = 0;

    if (session_params_metadata.exists(ANDROID_CONTROL_AE_TARGET_FPS_RANGE)) {
      frame_rate = ResolvedFrameRateFromMetadata(
          session_params_metadata, qualified_formats_, resolution, id_);
    } else {
      const SupportedFormat* format = FindFormatByResolution(
          qualified_formats_, resolution.width, resolution.height);
      DCHECK_NE(format, nullptr);
      frame_rate = GetMaximumFrameRate(*format);
    }

    constexpr int kMinPreviewFps = 15;
    // Select the resolution with the highest fps when
    // other resolutions have too low fps.
    if (frame_rate > streamon_params.frame_rate &&
        streamon_params.frame_rate < kMinPreviewFps) {
      streamon_params.resolution = resolution;
      streamon_params.frame_rate = frame_rate;
      continue;
    }

    // Skip resolutions with low fps.
    // Some devices, e.g. Kinect, do not enumerate any frame rates, see
    // |V4L2CameraDevice::GetFrameRateList()|. The fps is set to 0,
    // consider them as high fps.
    if (frame_rate != 0 && frame_rate < kMinPreviewFps) {
      continue;
    }

    // Find maximum area of stream_config to stream on.
    if (streamon_params.resolution < resolution) {
      streamon_params.resolution = resolution;
      streamon_params.frame_rate = frame_rate;
    }
  }

  {
    // Make sure |resolution| is not used outside of this scope.
    Size resolution(0, 0);
    streamon_params.use_native_sensor_ratio =
        ShouldUseNativeSensorRatio(*stream_config, &resolution);
    if (streamon_params.use_native_sensor_ratio) {
      streamon_params.resolution = resolution;
      const SupportedFormat* format = FindFormatByResolution(
          qualified_formats_, streamon_params.resolution.width,
          streamon_params.resolution.height);
      DCHECK_NE(format, nullptr);
      streamon_params.frame_rate = GetMaximumFrameRate(*format);
    }
  }

  std::string session_params_fps_range = "[]";
  if (session_params_metadata.exists(ANDROID_CONTROL_AE_TARGET_FPS_RANGE)) {
    auto fps_entry =
        session_params_metadata.find(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);
    session_params_fps_range = base::StringPrintf(
        "[%d,%d]", fps_entry.data.i32[0], fps_entry.data.i32[1]);
  }
  LOGF(INFO) << "size: " << streamon_params.resolution.ToString()
             << ", fps: " << streamon_params.frame_rate
             << ", crop_rotate_scale_degrees: "
             << streamon_params.crop_rotate_scale_degrees
             << ", use_native_sensor_ratio: "
             << streamon_params.use_native_sensor_ratio
             << ", session_parameters fps: " << session_params_fps_range;

  return base::ok(streamon_params);
}

base::expected<int, CameraClient::Error> CameraClient::StreamOn(
    const CameraClient::StreamOnParameters& streamon_params) {
  DCHECK(ops_thread_checker_.CalledOnValidThread());

  if (!request_handler_.get()) {
    if (!request_thread_.Start()) {
      LOGFID(ERROR, id_) << "Request thread failed to start";
      return base::unexpected(-EINVAL);
    }
    request_task_runner_ = request_thread_.task_runner();

    request_handler_ = std::make_unique<RequestHandler>(
        id_, device_info_, static_metadata_, device_.get(), callback_ops_,
        request_task_runner_, metadata_handler_.get(), sw_privacy_switch_on_);
  }

  auto future =
      cros::Future<base::expected<int, CameraClient::Error>>::Create(nullptr);
  base::OnceCallback<void(int, int)> streamon_callback =
      base::BindOnce(&CameraClient::StreamOnCallback, base::Unretained(this),
                     base::RetainedRef(future));
  request_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraClient::RequestHandler::StreamOn,
                                base::Unretained(request_handler_.get()),
                                streamon_params, std::move(streamon_callback)));
  return future->Get();
}

void CameraClient::StreamOff() {
  DCHECK(ops_thread_checker_.CalledOnValidThread());
  if (request_handler_.get()) {
    auto future = cros::Future<int>::Create(nullptr);
    base::OnceCallback<void(int)> streamoff_callback =
        base::BindOnce(&CameraClient::StreamOffCallback, base::Unretained(this),
                       base::RetainedRef(future));
    request_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraClient::RequestHandler::StreamOff,
                                  base::Unretained(request_handler_.get()),
                                  std::move(streamoff_callback)));
    int ret = future->Get();
    if (ret) {
      LOGFID(ERROR, id_) << "StreamOff failed";
    }
    request_thread_.Stop();
    request_handler_.reset();
  }
}

void CameraClient::StreamOnCallback(
    scoped_refptr<cros::Future<base::expected<int, CameraClient::Error>>>
        future,
    int num_buffers,
    CameraClient::Error error) {
  if (!error) {
    future->Set(base::ok(num_buffers));
  } else {
    future->Set(base::unexpected(error));
  }
}

void CameraClient::StreamOffCallback(scoped_refptr<cros::Future<Error>> future,
                                     Error error) {
  future->Set(error);
}

bool CameraClient::ShouldUseNativeSensorRatio(
    const camera3_stream_configuration_t& stream_config, Size* resolution) {
  if (device_info_.lens_facing == LensFacing::kExternal) {
    // We don't know the native sensor size for the external camera, so return
    // false here to prevent from using undefined
    // |device_info_.sensor_info_pixel_array_size_*|.
    return false;
  }

  bool try_native_sensor_ratio = false;

  // Check if we have different aspect ratio resolutions.
  // If the aspect ratios of all resolutions are the same we can use the
  // largest resolution and only do scale to others.
  float stream0_aspect_ratio =
      static_cast<float>(stream_config.streams[0]->width) /
      stream_config.streams[0]->height;
  for (size_t i = 1; i < stream_config.num_streams; i++) {
    float stream_aspect_ratio =
        static_cast<float>(stream_config.streams[i]->width) /
        stream_config.streams[i]->height;
    if (std::fabs(stream0_aspect_ratio - stream_aspect_ratio) >
        kAspectRatioMargin) {
      try_native_sensor_ratio = true;
      break;
    }
  }
  if (!try_native_sensor_ratio)
    return false;

  // Find maximum width and height of all streams.
  Size max_stream_resolution(0, 0);
  for (size_t i = 0; i < stream_config.num_streams; i++) {
    if (stream_config.streams[i]->width > max_stream_resolution.width) {
      max_stream_resolution.width = stream_config.streams[i]->width;
    }
    if (stream_config.streams[i]->height > max_stream_resolution.height) {
      max_stream_resolution.height = stream_config.streams[i]->height;
    }
  }

  bool use_native_sensor_ratio = false;
  // Find the same ratio maximium resolution with minimum 30 fps.
  float target_aspect_ratio =
      static_cast<float>(device_info_.sensor_info_pixel_array_size_width) /
      device_info_.sensor_info_pixel_array_size_height;

  resolution->width = std::numeric_limits<int>::max();
  resolution->height = std::numeric_limits<int>::max();

  VLOGFID(1, id_) << "native aspect ratio:" << target_aspect_ratio << ",("
                  << device_info_.sensor_info_pixel_array_size_width << ", "
                  << device_info_.sensor_info_pixel_array_size_height << ")"
                  << " Max " << max_stream_width_ << "x" << max_stream_height_;
  for (const auto& format : qualified_formats_) {
    float max_fps = GetMaximumFrameRate(format);
    if (max_fps < 29.0) {
      continue;
    }
    if (format.width > max_stream_width_ ||
        format.height > max_stream_height_) {
      continue;
    }
    if (format.width < max_stream_resolution.width ||
        format.height < max_stream_resolution.height) {
      continue;
    }
    // We choose the minimum resolution for the native aspect ratio.
    if (format.width > resolution->width ||
        format.height > resolution->height) {
      continue;
    }
    float aspect_ratio = static_cast<float>(format.width) / format.height;
    VLOGFID(2, id_) << "Try " << format.width << "," << format.height << "("
                    << aspect_ratio << ")";
    if (std::fabs(target_aspect_ratio - aspect_ratio) < kAspectRatioMargin) {
      resolution->width = format.width;
      resolution->height = format.height;
      use_native_sensor_ratio = true;
    }
  }
  LOGFID(INFO, id_) << "Use native sensor ratio:" << std::boolalpha
                    << use_native_sensor_ratio << " " << resolution->width
                    << "," << resolution->height;
  return use_native_sensor_ratio;
}

CameraClient::RequestHandler::RequestHandler(
    const int device_id,
    const DeviceInfo& device_info,
    const android::CameraMetadata& static_metadata,
    V4L2CameraDevice* device,
    const camera3_callback_ops_t* callback_ops,
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
    MetadataHandler* metadata_handler,
    bool sw_privacy_switch_on)
    : device_id_(device_id),
      device_info_(device_info),
      static_metadata_(static_metadata),
      device_(device),
      callback_ops_(callback_ops),
      task_runner_(task_runner),
      cached_frame_(static_metadata),
      metadata_handler_(metadata_handler),
      stream_on_fps_(0.0),
      stream_on_resolution_(0, 0),
      default_resolution_(0, 0),
      current_v4l2_buffer_id_(-1),
      current_buffer_timestamp_in_v4l2_(0),
      current_buffer_timestamp_in_user_(0),
      flush_started_(false),
      is_video_recording_(false),
      max_num_detected_faces_(0),
      sw_privacy_switch_on_(sw_privacy_switch_on) {
  SupportedFormats supported_formats =
      device_->GetDeviceSupportedFormats(device_info_.device_path);
  qualified_formats_ =
      GetQualifiedFormats(supported_formats, device_info_.quirks);
}

CameraClient::RequestHandler::~RequestHandler() {}

void CameraClient::RequestHandler::StreamOn(
    const CameraClient::StreamOnParameters& streamon_params,
    base::OnceCallback<void(int, int)> callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  crop_rotate_scale_degrees_ = streamon_params.crop_rotate_scale_degrees;

  const SupportedFormat* format = FindFormatByResolution(
      qualified_formats_, streamon_params.resolution.width,
      streamon_params.resolution.height);
  if (format == nullptr) {
    LOGFID(ERROR, device_id_)
        << "Cannot find resolution in supported list: width "
        << streamon_params.resolution.width << ", height "
        << streamon_params.resolution.height;
    std::move(callback).Run(0, -EINVAL);
    return;
  }
  int ret = StreamOnImpl(streamon_params);
  if (ret) {
    std::move(callback).Run(0, ret);
    return;
  }
  default_resolution_ = streamon_params.resolution;
  // Some camera modules need a lot of time to output the first frame.
  // It causes some CTS tests failed. Wait the first frame to be ready in
  // ConfigureStream can make sure there is no delay to output frames.
  // NOTE: ConfigureStream should be returned in 1000 ms.
  SkipFramesAfterStreamOn(1);
  std::move(callback).Run(input_buffers_.size(), 0);
}

void CameraClient::RequestHandler::StreamOff(
    base::OnceCallback<void(int)> callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  int ret = StreamOffImpl();
  std::move(callback).Run(ret);
}

void CameraClient::RequestHandler::HandleRequest(
    std::unique_ptr<CaptureRequest> request) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  camera3_capture_result_t capture_result;
  memset(&capture_result, 0, sizeof(camera3_capture_result_t));

  capture_result.frame_number = request->GetFrameNumber();

  std::vector<camera3_stream_buffer_t>* output_stream_buffers =
      request->GetStreamBuffers();
  capture_result.num_output_buffers = output_stream_buffers->size();
  capture_result.output_buffers = &(*output_stream_buffers)[0];

  if (flush_started_) {
    VLOGFID(1, device_id_) << "Request Frame:" << capture_result.frame_number
                           << " is aborted due to flush";
    AbortGrallocBufferSync(&capture_result);
    HandleAbortedRequest(&capture_result);
    return;
  }

  if (!WaitGrallocBufferSync(&capture_result)) {
    HandleAbortedRequest(&capture_result);
    return;
  }

  VLOGFID(1, device_id_) << "Request Frame:" << capture_result.frame_number
                         << ", Number of output buffers: "
                         << capture_result.num_output_buffers;
  android::CameraMetadata* metadata = request->GetMetadata();
  is_video_recording_ = IsVideoRecording(*metadata);

  bool stream_resolution_reconfigure = false;
  Size new_resolution = stream_on_resolution_;
  if (!use_native_sensor_ratio_) {
    // Decide the stream resolution for this request. If resolution change is
    // needed, we don't switch the resolution back in the end of request.
    // We keep the resolution until next request and see whether we need to
    // change current resolution.
    // When taking pictures, we always switch to the still capture resolution to
    // ensure it has the largest FoV. Since BLOB and still YUV buffers can be
    // requested from camera service for one still capture, we choose the
    // largest one among them.
    std::optional<Size> max_still_capture_size;
    for (size_t i = 0; i < capture_result.num_output_buffers; i++) {
      const camera3_stream_t* stream = capture_result.output_buffers[i].stream;
      const Size stream_size(stream->width, stream->height);
      if ((stream->format == HAL_PIXEL_FORMAT_BLOB ||
           stream->usage & GRALLOC_USAGE_STILL_CAPTURE) &&
          (!max_still_capture_size || *max_still_capture_size < stream_size)) {
        max_still_capture_size = stream_size;
      }
    }
    new_resolution = max_still_capture_size.value_or(default_resolution_);
    if (new_resolution != stream_on_resolution_) {
      stream_resolution_reconfigure = true;
    }
  }

  int target_frame_rate = ResolvedFrameRateFromMetadata(
      *metadata, qualified_formats_, new_resolution, device_id_);
  bool should_update_frame_rate =
      device_->CanUpdateFrameRate() &&
      target_frame_rate != device_->GetFrameRate() &&
      IsValidFrameRate(target_frame_rate);

  StreamOnParameters streamon_params = {
      .resolution = new_resolution,
      .crop_rotate_scale_degrees = use_native_sensor_ratio_,
      .frame_rate = target_frame_rate};

  if (stream_resolution_reconfigure || should_update_frame_rate ||
      sw_privacy_switch_error_occurred_) {
    VLOGFID(1, device_id_) << "Restart stream";
    int ret = StreamOffImpl();
    if (ret) {
      HandleAbortedRequest(&capture_result);
      return;
    }

    ret = StreamOnImpl(streamon_params);
    if (ret) {
      HandleAbortedRequest(&capture_result);
      return;
    }
    sw_privacy_switch_error_occurred_ = false;
  }

  // Get frame data from device only for the first buffer.
  // We reuse the buffer for all streams.
  int32_t pattern_mode = ANDROID_SENSOR_TEST_PATTERN_MODE_OFF;
  if (metadata->exists(ANDROID_SENSOR_TEST_PATTERN_MODE)) {
    camera_metadata_entry entry =
        metadata->find(ANDROID_SENSOR_TEST_PATTERN_MODE);
    pattern_mode = entry.data.i32[0];
  }

  int ret;
  bool keep_trying;
  do {
    VLOGFID(2, device_id_) << "before DequeueV4L2Buffer";
    ret = DequeueV4L2Buffer(pattern_mode);
    keep_trying = false;
    if (!ret) {
      if (metadata_handler_->PreHandleRequest(
              capture_result.frame_number, stream_on_resolution_, metadata)) {
        LOGFID(WARNING, device_id_)
            << "Update metadata in PreHandleRequest failed";
      }
      ret = WriteStreamBuffers(*metadata, &capture_result);
    } else if (ret == -ETIMEDOUT &&
               (device_info_.quirks & kQuirkRestartOnTimeout)) {
      VLOGFID(1, device_id_) << "Restart stream";
      if (StreamOffImpl() != 0) {
        break;
      }
      if (StreamOnImpl(streamon_params) != 0) {
        break;
      }
      keep_trying = true;
    }
    keep_trying = keep_trying || (ret == -EAGAIN);
  } while (keep_trying);

  if (ret) {
    HandleAbortedRequest(&capture_result);
    return;
  }

  // Return v4l2 buffer.
  ret = EnqueueV4L2Buffer();
  if (ret) {
    HandleAbortedRequest(&capture_result);
    return;
  }

  NotifyShutter(capture_result.frame_number);
  ret = metadata_handler_->PostHandleRequest(
      capture_result.frame_number, CurrentBufferTimestamp(),
      stream_on_resolution_, detected_faces_, metadata);
  if (ret) {
    LOGFID(WARNING, device_id_)
        << "Update metadata in PostHandleRequest failed";
  }

  capture_result.partial_result = 1;

  // We don't support logical multi camera currently.
  capture_result.num_physcam_metadata = 0;
  capture_result.physcam_ids = nullptr;
  capture_result.physcam_metadata = nullptr;

  // The HAL retains ownership of result structure, which only needs to be valid
  // to access during process_capture_result. The framework will copy whatever
  // it needs before process_capture_result returns. Hence we use getAndLock()
  // instead of release() here, and the underlying buffer would be freed when
  // metadata is out of scope.
  capture_result.result = metadata->getAndLock();

  // After process_capture_result, HAL cannot access the output buffer in
  // camera3_stream_buffer anymore unless the release fence is not -1.
  callback_ops_->process_capture_result(callback_ops_, &capture_result);
}

void CameraClient::RequestHandler::HandleFlush(
    base::OnceCallback<void(int)> callback) {
  VLOGFID(1, device_id_);
  {
    base::AutoLock l(flush_lock_);
    flush_started_ = true;
  }
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraClient::RequestHandler::FlushDone,
                                base::Unretained(this), std::move(callback)));
}

int CameraClient::RequestHandler::GetMaxNumDetectedFaces() {
  return max_num_detected_faces_;
}

void CameraClient::RequestHandler::SetPrivacySwitchState(bool on) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (sw_privacy_switch_on_ == on) {
    return;
  }
  sw_privacy_switch_on_ = on;
  if (device_->SetPrivacySwitchState(on) < 0) {
    LOGF(ERROR) << "Failed to set the SW privacy switch state to"
                << "V4L2CameraDevice";
    sw_privacy_switch_error_occurred_ = true;
    return;
  }
  frames_to_skip_after_privacy_switch_disabled_ =
      device_info_.frames_to_skip_after_streamon;
}

void CameraClient::RequestHandler::DiscardOutdatedBuffers() {
  int filled_count = 0;
  for (size_t i = 0; i < input_buffers_.size(); i++) {
    if (device_->IsBufferFilled(i)) {
      filled_count++;
    }
  }
  SkipFramesAfterStreamOn(filled_count);
}

int CameraClient::RequestHandler::StreamOnImpl(
    const CameraClient::StreamOnParameters& streamon_params) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  int ret;
  // If new stream configuration is the same as current stream, do nothing.
  if (streamon_params.resolution.width == stream_on_resolution_.width &&
      streamon_params.resolution.height == stream_on_resolution_.height &&
      streamon_params.use_native_sensor_ratio == use_native_sensor_ratio_ &&
      static_cast<float>(streamon_params.frame_rate) == stream_on_fps_) {
    VLOGFID(1, device_id_) << "Skip stream on for the same configuration";
    DiscardOutdatedBuffers();
    return 0;
  } else if (!input_buffers_.empty()) {
    // StreamOff first if stream is started.
    ret = StreamOffImpl();
    if (ret) {
      LOGFID(ERROR, device_id_) << "Restart stream failed.";
      return ret;
    }
  }
  const SupportedFormat* format = FindFormatByResolution(
      qualified_formats_, streamon_params.resolution.width,
      streamon_params.resolution.height);
  if (format == nullptr) {
    LOGFID(ERROR, device_id_)
        << "Cannot find resolution in supported list: width "
        << streamon_params.resolution.width << ", height "
        << streamon_params.resolution.height;
    return -EINVAL;
  }

  VLOGFID(1, device_id_) << "streamOn with width " << format->width
                         << ", height " << format->height << ", fps "
                         << streamon_params.frame_rate << ", format "
                         << FormatToString(format->fourcc);

  std::vector<base::ScopedFD> fds;
  std::vector<uint32_t> buffer_sizes;
  ret = device_->StreamOn(format->width, format->height, format->fourcc,
                          static_cast<float>(streamon_params.frame_rate), &fds,
                          &buffer_sizes);
  if (ret) {
    LOGFID(ERROR, device_id_)
        << "StreamOn failed: " << base::safe_strerror(-ret);
    return ret;
  }

  for (size_t i = 0; i < fds.size(); i++) {
    auto frame = std::make_unique<V4L2FrameBuffer>(
        std::move(fds[i]), buffer_sizes[i], format->width, format->height,
        format->fourcc);
    ret = frame->Map();
    if (ret) {
      return ret;
    }
    VLOGFID(1, device_id_) << "Buffer " << i << ", fd: " << frame->GetFd()
                           << " address: " << std::hex
                           << reinterpret_cast<uintptr_t>(frame->GetData())
                           << std::dec;
    input_buffers_.push_back(std::move(frame));
  }

  stream_on_resolution_ = streamon_params.resolution;
  use_native_sensor_ratio_ = streamon_params.use_native_sensor_ratio;
  stream_on_fps_ = static_cast<float>(streamon_params.frame_rate);
  current_buffer_timestamp_in_v4l2_ = 0;
  current_buffer_timestamp_in_user_ = 0;
  SkipFramesAfterStreamOn(device_info_.frames_to_skip_after_streamon);

  // Reset test pattern.
  auto entry = static_metadata_.find(ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE);
  if (entry.count == 0) {
    LOGF(ERROR) << "Failed to find pixel array size";
    return -EINVAL;
  }
  test_pattern_.reset(new TestPattern(
      Size(entry.data.i32[0], entry.data.i32[1]), stream_on_resolution_));
  InitializeBlackFrame();
  return 0;
}

int CameraClient::RequestHandler::StreamOffImpl() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  input_buffers_.clear();
  int ret = device_->StreamOff();
  if (ret) {
    LOGFID(ERROR, device_id_)
        << "StreamOff failed: " << base::safe_strerror(-ret);
  }
  stream_on_resolution_.width = stream_on_resolution_.height = 0;
  return ret;
}

void CameraClient::RequestHandler::HandleAbortedRequest(
    camera3_capture_result_t* capture_result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  for (size_t i = 0; i < capture_result->num_output_buffers; i++) {
    camera3_stream_buffer_t* b = const_cast<camera3_stream_buffer_t*>(
        capture_result->output_buffers + i);
    b->status = CAMERA3_BUFFER_STATUS_ERROR;
  }
  NotifyRequestError(capture_result->frame_number);
  callback_ops_->process_capture_result(callback_ops_, capture_result);
}

bool CameraClient::RequestHandler::IsVideoRecording(
    const android::CameraMetadata& metadata) {
  if (metadata.exists(ANDROID_CONTROL_CAPTURE_INTENT)) {
    camera_metadata_ro_entry entry =
        metadata.find(ANDROID_CONTROL_CAPTURE_INTENT);
    switch (entry.data.u8[0]) {
      case ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_RECORD:
      case ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_SNAPSHOT:
        return true;
    }
  }
  return false;
}

bool CameraClient::RequestHandler::IsExternalCamera() {
  return device_info_.lens_facing == LensFacing::kExternal;
}

uint64_t CameraClient::RequestHandler::CurrentBufferTimestamp() {
  return device_info_.quirks & kQuirkUserSpaceTimestamp
             ? current_buffer_timestamp_in_user_
             : current_buffer_timestamp_in_v4l2_;
}

bool CameraClient::RequestHandler::IsValidFrameRate(int frame_rate) {
  camera_metadata_ro_entry entry =
      static_metadata_.find(ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES);
  for (size_t i = 1; i < entry.count; i += 2) {
    // Available fps ranges are listed as [[min_1, max_1], [min_2, max_2], ...].
    // The frame rate is valid if it equals to the max value of any set.
    if (frame_rate == entry.data.i32[i]) {
      return true;
    }
  }
  return false;
}

int CameraClient::RequestHandler::WriteStreamBuffers(
    const android::CameraMetadata& request_metadata,
    camera3_capture_result_t* capture_result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_USB_HAL("frame_number", capture_result->frame_number);

  std::vector<std::unique_ptr<FrameBuffer>> output_frames;
  for (size_t i = 0; i < capture_result->num_output_buffers; i++) {
    const camera3_stream_buffer_t* buffer = &capture_result->output_buffers[i];
    VLOGFID(1, device_id_) << "output buffer stream format: "
                           << buffer->stream->format
                           << ", buffer ptr: " << *buffer->buffer
                           << ", width: " << buffer->stream->width
                           << ", height: " << buffer->stream->height;
    output_frames.push_back(std::make_unique<GrallocFrameBuffer>(
        *buffer->buffer, buffer->stream->width, buffer->stream->height));
  }

  FrameBuffer* input_frame;
  if (sw_privacy_switch_on_ ||
      frames_to_skip_after_privacy_switch_disabled_ > 0) {
    --frames_to_skip_after_privacy_switch_disabled_;
    input_frame = black_frame_.get();
  } else if (test_pattern_->IsTestPatternEnabled()) {
    input_frame = test_pattern_->GetTestPattern();
  } else {
    input_frame = input_buffers_[current_v4l2_buffer_id_].get();
  }

  std::vector<int> output_frame_status;
  std::vector<human_sensing::CrosFace>* faces_ptr =
      device_info_.enable_face_detection ? &detected_faces_ : nullptr;
  int ret = cached_frame_.Convert(
      static_metadata_, request_metadata, crop_rotate_scale_degrees_,
      *input_frame, output_frames, output_frame_status, faces_ptr);

  if (ret) {
    EnqueueV4L2Buffer();
    return ret;
  }
  max_num_detected_faces_ =
      std::max(max_num_detected_faces_, detected_faces_.size());

  for (size_t i = 0; i < capture_result->num_output_buffers; i++) {
    camera3_stream_buffer_t* b = const_cast<camera3_stream_buffer_t*>(
        capture_result->output_buffers + i);
    if (output_frame_status[i]) {
      LOGFID(ERROR, device_id_)
          << "Handle stream buffer failed for output buffer id: " << i;
      b->status = CAMERA3_BUFFER_STATUS_ERROR;
    } else {
      b->status = CAMERA3_BUFFER_STATUS_OK;
    }
  }
  return 0;
}

void CameraClient::RequestHandler::SkipFramesAfterStreamOn(int num_frames) {
  for (size_t i = 0; i < num_frames; i++) {
    uint32_t buffer_id, data_size;
    uint64_t v4l2_ts, user_ts;
    int ret =
        device_->GetNextFrameBuffer(&buffer_id, &data_size, &v4l2_ts, &user_ts);
    if (!ret) {
      current_buffer_timestamp_in_v4l2_ = v4l2_ts;
      current_buffer_timestamp_in_user_ = user_ts;
      device_->ReuseFrameBuffer(buffer_id);
    } else {
      VLOGFID(1, device_id_)
          << "GetNextFrameBuffer failed: " << base::safe_strerror(-ret);
    }
  }
}

bool CameraClient::RequestHandler::WaitGrallocBufferSync(
    camera3_capture_result_t* capture_result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  // Framework allow 4 intervals delay. If fps is 30, 4 intervals delay is
  // 132ms. Use 300ms should be enough.
  const int kSyncWaitTimeoutMs = 300;
  bool fence_timeout = false;
  for (size_t i = 0; i < capture_result->num_output_buffers; i++) {
    camera3_stream_buffer_t* b = const_cast<camera3_stream_buffer_t*>(
        capture_result->output_buffers + i);
    if (b->acquire_fence == kBufferFenceReady) {
      continue;
    }

    int ret = sync_wait(b->acquire_fence, kSyncWaitTimeoutMs);
    if (ret) {
      // If buffer is not ready, set |release_fence| to notify framework to
      // wait the buffer again.
      b->release_fence = b->acquire_fence;
      LOGFID(ERROR, device_id_)
          << "Fence sync_wait failed: " << b->acquire_fence;
      fence_timeout = true;
    } else {
      close(b->acquire_fence);
    }

    // HAL has to set |acquire_fence| to -1 for output buffers.
    b->acquire_fence = kBufferFenceReady;
  }
  return !fence_timeout;
}

void CameraClient::RequestHandler::AbortGrallocBufferSync(
    camera3_capture_result_t* capture_result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  for (size_t i = 0; i < capture_result->num_output_buffers; i++) {
    camera3_stream_buffer_t* b = const_cast<camera3_stream_buffer_t*>(
        capture_result->output_buffers + i);
    b->release_fence = b->acquire_fence;
    b->acquire_fence = kBufferFenceReady;
  }
}

void CameraClient::RequestHandler::NotifyShutter(uint32_t frame_number) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  camera3_notify_msg_t m;
  memset(&m, 0, sizeof(m));
  m.type = CAMERA3_MSG_SHUTTER;
  m.message.shutter.frame_number = frame_number;
  m.message.shutter.timestamp = CurrentBufferTimestamp();
  callback_ops_->notify(callback_ops_, &m);
}

void CameraClient::RequestHandler::NotifyRequestError(uint32_t frame_number) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  camera3_notify_msg_t m;
  memset(&m, 0, sizeof(m));
  m.type = CAMERA3_MSG_ERROR;
  m.message.error.frame_number = frame_number;
  m.message.error.error_stream = nullptr;
  m.message.error.error_code = CAMERA3_MSG_ERROR_REQUEST;
  callback_ops_->notify(callback_ops_, &m);
}

int CameraClient::RequestHandler::DequeueV4L2Buffer(int32_t pattern_mode) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  int ret;
  if (sw_privacy_switch_on_) {
    // Wait for |delta| ns to keep the frame rate constant.
    struct timespec ts;
    ret = V4L2CameraDevice::GetUserSpaceTimestamp(ts);
    if (ret < 0) {
      return ret;
    }
    uint64_t target_ts_ns = current_buffer_timestamp_in_user_ +
                            static_cast<uint64_t>(1e9 / stream_on_fps_);
    uint64_t current_ts_ns = ts.tv_sec * 1'000'000'000LL + ts.tv_nsec;
    if (target_ts_ns > current_ts_ns) {
      base::PlatformThread::Sleep(
          base::Nanoseconds(target_ts_ns - current_ts_ns));
    }
    ret = V4L2CameraDevice::GetUserSpaceTimestamp(ts);
    if (ret < 0) {
      return ret;
    }
    uint64_t previous_buffer_timestamp_in_user_ =
        current_buffer_timestamp_in_user_;
    current_buffer_timestamp_in_user_ =
        ts.tv_sec * 1'000'000'000LL + ts.tv_nsec;
    // Increment |current_buffer_timestamp_in_v4l2_| by the same amount as
    // |current_buffer_timestamp_in_user_|. |current_buffer_timestamp_in_v4l2_|
    // needs to be monotonically increasing.
    current_buffer_timestamp_in_v4l2_ +=
        current_buffer_timestamp_in_user_ - previous_buffer_timestamp_in_user_;
    return 0;
  }

  uint32_t buffer_id = 0, data_size = 0;
  uint64_t v4l2_ts, user_ts;
  uint64_t delta_user_ts = 0, delta_v4l2_ts = 0;
  // If frame duration between user space and v4l2 buffer shifts 20%,
  // we should return next frame.
  const uint64_t allowed_shift_frame_duration_ns =
      static_cast<uint64_t>((1e9 / stream_on_fps_) * 0.2);
  size_t drop_count = 0;

  // Some requests take a long time and cause several frames are buffered in
  // V4L2 buffers in UVC driver. It causes user can get several frames during
  // one frame duration when user send capture requests seamlessly. We should
  // drop out-of-date frames to pass testResultTimestamps CTS test.
  // See b/119635561 for detail.
  // Since UVC HW timestamp may error when UVC driver drops frames, we at most
  // drop the size of |input_buffers_| frames here to avoid infinite loop.
  // TODO(henryhsu): Have another thread to fetch frame and report latest one.
  do {
    if (delta_user_ts > 0) {
      VLOGF(1) << "Drop outdated frame: delta_user_ts = " << delta_user_ts
               << ", delta_v4l2_ts = " << delta_v4l2_ts;
      device_->ReuseFrameBuffer(buffer_id);
      drop_count++;
      if (ret) {
        LOGFID(ERROR, device_id_)
            << "ReuseFrameBuffer failed: " << base::safe_strerror(-ret)
            << " for input buffer id: " << buffer_id;
        return ret;
      }
    }
    // If device_->GetNextFrameBuffer returns error, the buffer is still in
    // driver side. Therefore we don't need to enqueue the buffer.
    ret =
        device_->GetNextFrameBuffer(&buffer_id, &data_size, &v4l2_ts, &user_ts);
    if (ret) {
      LOGFID_THROTTLED(ERROR, device_id_, 60)
          << "GetNextFrameBuffer failed: " << base::safe_strerror(-ret);
      return ret;
    }
    // If this is the first frame after stream on, just use it.
    if (current_buffer_timestamp_in_v4l2_ == 0) {
      break;
    }

    delta_user_ts = user_ts - current_buffer_timestamp_in_user_;
    delta_v4l2_ts = v4l2_ts - current_buffer_timestamp_in_v4l2_;

    // Some special conditions:
    // 1. Do not drop frames for video recording because we don't want to skip
    //    frames in the video.
    // 2. Do not drop frames for external camera, because it may not support
    //    constant frame rate and the hardware timestamp is not stable enough.
  } while (!is_video_recording_ && !IsExternalCamera() &&
           allowed_shift_frame_duration_ns + delta_v4l2_ts < delta_user_ts &&
           drop_count < input_buffers_.size());
  current_buffer_timestamp_in_user_ = user_ts;
  current_buffer_timestamp_in_v4l2_ = v4l2_ts;

  // after this part, we got a buffer from V4L2 device,
  // so we need to return the buffer back if any error happens.
  current_v4l2_buffer_id_ = buffer_id;

  ret = input_buffers_[buffer_id]->SetDataSize(data_size);
  if (ret) {
    LOGFID(ERROR, device_id_)
        << "Set data size failed for input buffer id: " << buffer_id;
    EnqueueV4L2Buffer();
    return ret;
  }

  if (!test_pattern_->SetTestPatternMode(pattern_mode)) {
    EnqueueV4L2Buffer();
    return -EINVAL;
  }

  return 0;
}

int CameraClient::RequestHandler::EnqueueV4L2Buffer() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (sw_privacy_switch_on_) {
    return 0;
  }
  int ret = device_->ReuseFrameBuffer(current_v4l2_buffer_id_);
  if (ret) {
    LOGFID(ERROR, device_id_)
        << "ReuseFrameBuffer failed: " << base::safe_strerror(-ret)
        << " for input buffer id: " << current_v4l2_buffer_id_;
  }
  current_v4l2_buffer_id_ = -1;
  return ret;
}

void CameraClient::RequestHandler::FlushDone(
    base::OnceCallback<void(int)> callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  VLOGFID(1, device_id_);
  std::move(callback).Run(0);
  {
    base::AutoLock l(flush_lock_);
    flush_started_ = false;
  }
}

void CameraClient::RequestHandler::InitializeBlackFrame() {
  int number_of_pixels =
      stream_on_resolution_.width * stream_on_resolution_.height;
  black_frame_ = std::make_unique<SharedFrameBuffer>(number_of_pixels * 1.5);
  black_frame_->SetFourcc(V4L2_PIX_FMT_YUV420);
  black_frame_->SetWidth(stream_on_resolution_.width);
  black_frame_->SetHeight(stream_on_resolution_.height);
  black_frame_->SetDataSize(number_of_pixels * 1.5);
  uint8_t* data = black_frame_->GetData();
  memset(data, 0, number_of_pixels);
  memset(data + number_of_pixels, 128, number_of_pixels / 2);
}

}  // namespace cros
