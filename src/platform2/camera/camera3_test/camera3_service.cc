// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_service.h"

#include <unistd.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>

#include "camera3_test/camera3_perf_log.h"
#include "cros-camera/common.h"

namespace camera3_test {

namespace {

constexpr int kWaitForStopPreviewTimeoutMs = 3000;
constexpr int kWaitForStopRecordingTimeoutMs = 3000;

double Get3ATimeoutMultiplier() {
  static double multiplier = [] {
    constexpr char kSwitch[] = "3a_timeout_multiplier";
    const auto* cl = base::CommandLine::ForCurrentProcess();
    std::string val = cl->GetSwitchValueASCII(kSwitch);
    double out;
    if (val.empty() || !base::StringToDouble(val, &out)) {
      return 1.0;
    }
    return out;
  }();
  return multiplier;
}

int GetWaitForFocusDoneTimeoutMs() {
  return static_cast<int>(6000 * Get3ATimeoutMultiplier());
}

int GetWaitForAWBConvergedTimeoutMs() {
  return static_cast<int>(3000 * Get3ATimeoutMultiplier());
}

}  // namespace

Camera3Service::~Camera3Service() {}

int Camera3Service::Initialize(
    ProcessStillCaptureResultCallback still_capture_cb,
    ProcessRecordingResultCallback recording_cb,
    ProcessPreviewResultCallback preview_cb) {
  base::AutoLock l(lock_);
  if (initialized_) {
    LOGF(ERROR) << "Camera service is already initialized";
    return -EINVAL;
  }
  for (const auto& it : cam_ids_) {
    cam_dev_service_map_[it].reset(new Camera3Service::Camera3DeviceService(
        it, still_capture_cb, recording_cb, preview_cb));
    int result = cam_dev_service_map_[it]->Initialize();
    if (result != 0) {
      LOGF(ERROR) << "Camera device " << it << " service initialization fails";
      cam_dev_service_map_.clear();
      return result;
    }
  }
  initialized_ = true;
  return 0;
}

void Camera3Service::Destroy() {
  base::AutoLock l(lock_);
  if (!initialized_) {
    return;
  }
  for (auto& it : cam_dev_service_map_) {
    it.second->Destroy();
  }
  cam_dev_service_map_.clear();
  initialized_ = false;
}

int Camera3Service::StartPreview(int cam_id,
                                 const ResolutionInfo& preview_resolution,
                                 const ResolutionInfo& still_capture_resolution,
                                 const ResolutionInfo& recording_resolution) {
  base::AutoLock l(lock_);
  if (!initialized_ ||
      cam_dev_service_map_.find(cam_id) == cam_dev_service_map_.end()) {
    return -ENODEV;
  }
  return cam_dev_service_map_[cam_id]->StartPreview(
      preview_resolution, still_capture_resolution, recording_resolution);
}

void Camera3Service::StopPreview(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->StopPreview();
  }
}

void Camera3Service::StartAutoFocus(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->StartAutoFocus();
  }
}

int Camera3Service::WaitForAutoFocusDone(int cam_id) {
  base::AutoLock l(lock_);
  if (!initialized_ ||
      cam_dev_service_map_.find(cam_id) == cam_dev_service_map_.end()) {
    return -ENODEV;
  }
  return cam_dev_service_map_[cam_id]->WaitForAutoFocusDone();
}

int Camera3Service::WaitForAWBConvergedAndLock(int cam_id) {
  base::AutoLock l(lock_);
  if (!initialized_ ||
      cam_dev_service_map_.find(cam_id) == cam_dev_service_map_.end()) {
    return -ENODEV;
  }
  return cam_dev_service_map_[cam_id]->WaitForAWBConvergedAndLock();
}

void Camera3Service::StartAEPrecapture(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->StartAEPrecapture();
  }
}

int Camera3Service::WaitForAEStable(int cam_id) {
  base::AutoLock l(lock_);
  if (!initialized_ ||
      cam_dev_service_map_.find(cam_id) == cam_dev_service_map_.end()) {
    return -ENODEV;
  }
  return cam_dev_service_map_[cam_id]->WaitForAEStable();
}

void Camera3Service::StartFaceDetection(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->StartFaceDetection();
  }
}

void Camera3Service::StopFaceDetection(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->StopFaceDetection();
  }
}

void Camera3Service::TakeStillCapture(int cam_id,
                                      const camera_metadata_t* metadata) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->TakeStillCapture(metadata);
  }
}

int Camera3Service::StartRecording(int cam_id,
                                   const camera_metadata_t* metadata) {
  base::AutoLock l(lock_);
  if (!initialized_ ||
      cam_dev_service_map_.find(cam_id) == cam_dev_service_map_.end()) {
    return -ENODEV;
  }
  return cam_dev_service_map_[cam_id]->StartRecording(metadata);
}

void Camera3Service::StopRecording(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    cam_dev_service_map_[cam_id]->StopRecording();
  }
}

int Camera3Service::WaitForPreviewFrames(int cam_id,
                                         uint32_t num_frames,
                                         uint32_t timeout_ms) {
  base::AutoLock l(lock_);
  if (!initialized_ ||
      cam_dev_service_map_.find(cam_id) == cam_dev_service_map_.end()) {
    return -ENODEV;
  }
  return cam_dev_service_map_[cam_id]->WaitForPreviewFrames(num_frames,
                                                            timeout_ms);
}

const Camera3Device::StaticInfo* Camera3Service::GetStaticInfo(int cam_id) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    return cam_dev_service_map_[cam_id]->GetStaticInfo();
  }
  return nullptr;
}

const camera_metadata_t* Camera3Service::ConstructDefaultRequestSettings(
    int cam_id, int type) {
  base::AutoLock l(lock_);
  if (initialized_ &&
      cam_dev_service_map_.find(cam_id) != cam_dev_service_map_.end()) {
    return cam_dev_service_map_[cam_id]->ConstructDefaultRequestSettings(type);
  }
  return nullptr;
}

int Camera3Service::Camera3DeviceService::Initialize() {
  Camera3Module cam_module;
  if (cam_device_.Initialize(&cam_module) != 0) {
    LOGF(ERROR) << "Camera device initialization fails";
    return -ENODEV;
  }
  if (!service_thread_.Start()) {
    LOGF(ERROR) << "Failed to start thread";
    return -EINVAL;
  }
  cam_device_.RegisterResultMetadataOutputBufferCallback(base::BindRepeating(
      &Camera3Service::Camera3DeviceService::ProcessResultMetadataOutputBuffers,
      base::Unretained(this)));
  repeating_preview_metadata_.reset(clone_camera_metadata(
      cam_device_.ConstructDefaultRequestSettings(CAMERA3_TEMPLATE_PREVIEW)));
  if (!repeating_preview_metadata_) {
    LOGF(ERROR) << "Failed to create preview metadata";
    return -ENOMEM;
  }
  sem_init(&preview_frame_sem_, 0, 0);
  return 0;
}

void Camera3Service::Camera3DeviceService::Destroy() {
  service_thread_.Stop();
  sem_destroy(&preview_frame_sem_);
  cam_device_.Destroy();
}

int Camera3Service::Camera3DeviceService::StartPreview(
    const ResolutionInfo& preview_resolution,
    const ResolutionInfo& still_capture_resolution,
    const ResolutionInfo& recording_resolution) {
  int result = -EIO;
  service_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &Camera3Service::Camera3DeviceService::StartPreviewOnServiceThread,
          base::Unretained(this), preview_resolution, still_capture_resolution,
          recording_resolution, &result));
  return result;
}

void Camera3Service::Camera3DeviceService::StopPreview() {
  auto future = cros::Future<void>::Create(nullptr);
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(
          &Camera3Service::Camera3DeviceService::StopPreviewOnServiceThread,
          base::Unretained(this), cros::GetFutureCallback(future)));
  if (!future->Wait(kWaitForStopPreviewTimeoutMs)) {
    LOGF(ERROR) << "Timeout stopping preview";
  }
}

void Camera3Service::Camera3DeviceService::StartAutoFocus() {
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(
          &Camera3Service::Camera3DeviceService::StartAutoFocusOnServiceThread,
          base::Unretained(this)));
}

int Camera3Service::Camera3DeviceService::WaitForAutoFocusDone() {
  auto future = cros::Future<void>::Create(nullptr);
  int32_t result;
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(&Camera3Service::Camera3DeviceService::
                         AddMetadataListenerOnServiceThread,
                     base::Unretained(this), ANDROID_CONTROL_AF_STATE,
                     std::unordered_set<int32_t>(
                         {ANDROID_CONTROL_AF_STATE_FOCUSED_LOCKED,
                          ANDROID_CONTROL_AF_STATE_NOT_FOCUSED_LOCKED}),
                     cros::GetFutureCallback(future), &result));
  if (!future->Wait(GetWaitForFocusDoneTimeoutMs())) {
    service_thread_.PostTaskSync(
        FROM_HERE,
        base::BindOnce(&Camera3Service::Camera3DeviceService::
                           DeleteMetadataListenerOnServiceThread,
                       base::Unretained(this), ANDROID_CONTROL_AF_STATE,
                       std::unordered_set<int32_t>(
                           {ANDROID_CONTROL_AF_STATE_FOCUSED_LOCKED,
                            ANDROID_CONTROL_AF_STATE_NOT_FOCUSED_LOCKED})));
    return -ETIMEDOUT;
  }
  if (result == ANDROID_CONTROL_AF_STATE_NOT_FOCUSED_LOCKED) {
    VLOGF(1) << "Auto-focus did not lock";
  }
  return 0;
}

int Camera3Service::Camera3DeviceService::WaitForAWBConvergedAndLock() {
  auto future = cros::Future<void>::Create(nullptr);
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(
          &Camera3Service::Camera3DeviceService::
              AddMetadataListenerOnServiceThread,
          base::Unretained(this), ANDROID_CONTROL_AWB_STATE,
          std::unordered_set<int32_t>({ANDROID_CONTROL_AWB_STATE_CONVERGED}),
          cros::GetFutureCallback(future), nullptr));
  if (!future->Wait(GetWaitForAWBConvergedTimeoutMs())) {
    service_thread_.PostTaskSync(
        FROM_HERE,
        base::BindOnce(&Camera3Service::Camera3DeviceService::
                           DeleteMetadataListenerOnServiceThread,
                       base::Unretained(this), ANDROID_CONTROL_AWB_STATE,
                       std::unordered_set<int32_t>(
                           {ANDROID_CONTROL_AWB_STATE_CONVERGED})));
    return -ETIMEDOUT;
  }

  if (cam_device_.GetStaticInfo()->IsAWBLockSupported()) {
    service_thread_.PostTaskAsync(
        FROM_HERE,
        base::BindOnce(
            &Camera3Service::Camera3DeviceService::LockAWBOnServiceThread,
            base::Unretained(this)));
  }
  return 0;
}

void Camera3Service::Camera3DeviceService::StartAEPrecapture() {
  service_thread_.PostTaskAsync(
      FROM_HERE, base::BindOnce(&Camera3Service::Camera3DeviceService::
                                    StartAEPrecaptureOnServiceThread,
                                base::Unretained(this)));
}

int Camera3Service::Camera3DeviceService::WaitForAEStable() {
  auto future = cros::Future<void>::Create(nullptr);
  int32_t result;
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(&Camera3Service::Camera3DeviceService::
                         AddMetadataListenerOnServiceThread,
                     base::Unretained(this), ANDROID_CONTROL_AE_STATE,
                     std::unordered_set<int32_t>(
                         {ANDROID_CONTROL_AE_STATE_CONVERGED,
                          ANDROID_CONTROL_AE_STATE_FLASH_REQUIRED}),
                     cros::GetFutureCallback(future), &result));
  if (!future->Wait(GetWaitForFocusDoneTimeoutMs())) {
    service_thread_.PostTaskSync(
        FROM_HERE,
        base::BindOnce(&Camera3Service::Camera3DeviceService::
                           DeleteMetadataListenerOnServiceThread,
                       base::Unretained(this), ANDROID_CONTROL_AE_STATE,
                       std::unordered_set<int32_t>(
                           {ANDROID_CONTROL_AE_STATE_CONVERGED,
                            ANDROID_CONTROL_AE_STATE_FLASH_REQUIRED})));
    return -ETIMEDOUT;
  }
  if (result == ANDROID_CONTROL_AE_STATE_FLASH_REQUIRED) {
    VLOGF(1) << "Flash needs to be fired for good quality still capture";
  }
  return 0;
}

void Camera3Service::Camera3DeviceService::StartFaceDetection() {
  service_thread_.PostTaskAsync(
      FROM_HERE, base::BindOnce(&Camera3Service::Camera3DeviceService::
                                    StartFaceDetectionOnServiceThread,
                                base::Unretained(this)));
}

void Camera3Service::Camera3DeviceService::StopFaceDetection() {
  service_thread_.PostTaskAsync(
      FROM_HERE, base::BindOnce(&Camera3Service::Camera3DeviceService::
                                    StopFaceDetectionOnServiceThread,
                                base::Unretained(this)));
}

void Camera3Service::Camera3DeviceService::TakeStillCapture(
    const camera_metadata_t* metadata) {
  auto future = cros::Future<void>::Create(nullptr);
  service_thread_.PostTaskAsync(
      FROM_HERE, base::BindOnce(&Camera3Service::Camera3DeviceService::
                                    TakeStillCaptureOnServiceThread,
                                base::Unretained(this), metadata,
                                cros::GetFutureCallback(future)));
  // Wait for ProcessPreviewRequestOnServiceThread() to finish processing
  // |metadata|
  future->Wait();
}

int Camera3Service::Camera3DeviceService::StartRecording(
    const camera_metadata_t* metadata) {
  auto future = cros::Future<int>::Create(nullptr);
  service_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &Camera3Service::Camera3DeviceService::StartRecordingOnServiceThread,
          base::Unretained(this), metadata, cros::GetFutureCallback(future)));
  return future->Wait();
}

void Camera3Service::Camera3DeviceService::StopRecording() {
  auto future = cros::Future<void>::Create(nullptr);
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(
          &Camera3Service::Camera3DeviceService::StopRecordingOnServiceThread,
          base::Unretained(this), cros::GetFutureCallback(future)));
  if (!future->Wait(kWaitForStopRecordingTimeoutMs)) {
    LOGF(ERROR) << "Timeout stopping preview";
  }
}

int Camera3Service::Camera3DeviceService::WaitForPreviewFrames(
    uint32_t num_frames, uint32_t timeout_ms) {
  while (sem_trywait(&preview_frame_sem_) == 0) {
  }
  for (uint32_t i = 0; i < num_frames; ++i) {
    struct timespec timeout = {};
    if (clock_gettime(CLOCK_REALTIME, &timeout)) {
      LOGF(ERROR) << "Failed to get clock time";
      return -errno;
    }
    timeout.tv_sec += timeout_ms / 1000;
    timeout.tv_nsec += (timeout_ms % 1000) * 1000;
    if (sem_timedwait(&preview_frame_sem_, &timeout) != 0) {
      return -errno;
    }
  }
  return 0;
}

const Camera3Device::StaticInfo*
Camera3Service::Camera3DeviceService::GetStaticInfo() const {
  return cam_device_.GetStaticInfo();
}

const camera_metadata_t*
Camera3Service::Camera3DeviceService::ConstructDefaultRequestSettings(
    int type) {
  return cam_device_.ConstructDefaultRequestSettings(type);
}

void Camera3Service::Camera3DeviceService::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  service_thread_.PostTaskAsync(
      FROM_HERE,
      base::BindOnce(&Camera3Service::Camera3DeviceService::
                         ProcessResultMetadataOutputBuffersOnServiceThread,
                     base::Unretained(this), frame_number, std::move(metadata),
                     std::move(buffers)));
}

void Camera3Service::Camera3DeviceService::StartPreviewOnServiceThread(
    const ResolutionInfo preview_resolution,
    const ResolutionInfo still_capture_resolution,
    const ResolutionInfo recording_resolution,
    int* result) {
  DCHECK(service_thread_.IsCurrentThread());

  if (preview_state_ != PREVIEW_STOPPED) {
    LOGF(ERROR) << "Failed to start preview because it is not stopped";
    *result = -EAGAIN;
    return;
  }

  if (still_capture_resolution.Area()) {
    cam_device_.AddOutputStream(
        HAL_PIXEL_FORMAT_BLOB, still_capture_resolution.Width(),
        still_capture_resolution.Height(), CAMERA3_STREAM_ROTATION_0);
  }
  if (recording_resolution.Area()) {
    cam_device_.AddOutputStream(
        HAL_PIXEL_FORMAT_YCbCr_420_888, recording_resolution.Width(),
        recording_resolution.Height(), CAMERA3_STREAM_ROTATION_0);
    // Use recording template for preview to sync camera3_recording_test
    // with CTS testBasicRecording. See b/269378305 for details.
    repeating_preview_metadata_.reset(
        clone_camera_metadata(cam_device_.ConstructDefaultRequestSettings(
            CAMERA3_TEMPLATE_VIDEO_RECORD)));
    if (!repeating_preview_metadata_) {
      LOGF(ERROR) << "Failed to create preview metadata";
      *result = -ENOMEM;
      return;
    }
  }
  cam_device_.AddOutputStream(
      HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED, preview_resolution.Width(),
      preview_resolution.Height(), CAMERA3_STREAM_ROTATION_0);
  if (cam_device_.ConfigureStreams(&streams_) != 0) {
    ADD_FAILURE() << "Configuring stream fails";
    *result = -EINVAL;
    return;
  }
  auto GetStream = [this](int format) {
    auto it = std::find_if(streams_.begin(), streams_.end(),
                           [&](const camera3_stream_t* stream) {
                             return (stream->format == format);
                           });
    return (it == streams_.end()) ? nullptr : *it;
  };
  const camera3_stream_t* preview_stream =
      GetStream(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
  const camera3_stream_t* record_stream =
      GetStream(HAL_PIXEL_FORMAT_YCbCr_420_888);
  if (!preview_stream || (recording_resolution.Area() && !record_stream)) {
    ADD_FAILURE() << "Failed to find configured stream";
    *result = -EINVAL;
    return;
  }

  number_of_capture_requests_ = preview_stream->max_buffers;
  if (recording_resolution.Area()) {
    number_of_capture_requests_ =
        std::min(number_of_capture_requests_, record_stream->max_buffers);
  }
  capture_requests_.resize(number_of_capture_requests_);
  output_stream_buffers_ = std::vector<std::vector<camera3_stream_buffer_t>>(
      number_of_capture_requests_,
      std::vector<camera3_stream_buffer_t>(kNumberOfOutputStreamBuffers));
  // Submit initial preview capture requests to fill the HAL pipeline first.
  // Then when a result callback is processed, the corresponding capture
  // request (and output buffer) is recycled and submitted again.
  for (uint32_t i = 0; i < number_of_capture_requests_; i++) {
    std::vector<const camera3_stream_t*> streams(1, preview_stream);
    std::vector<camera3_stream_buffer_t> output_buffers;
    if (cam_device_.AllocateOutputBuffersByStreams(streams, &output_buffers) !=
        0) {
      ADD_FAILURE() << "Failed to allocate output buffer";
      *result = -EINVAL;
      return;
    }
    output_stream_buffers_[i][kPreviewOutputStreamIdx] = output_buffers.front();
    capture_requests_[i] = std::make_pair(
        camera3_capture_request_t{
            .frame_number =
                UINT32_MAX,  // Will be overwritten with correct value
            .settings = repeating_preview_metadata_.get(),
            .input_buffer = NULL,
            .num_output_buffers = 1,
            .output_buffers = output_stream_buffers_[i].data(),
            .num_physcam_settings = 0},
        false);
    ProcessPreviewRequestOnServiceThread();
  }
  preview_state_ = PREVIEW_STARTING;
  *result = 0;
}

void Camera3Service::Camera3DeviceService::StopPreviewOnServiceThread(
    base::OnceCallback<void()> cb) {
  DCHECK(service_thread_.IsCurrentThread());

  if (preview_state_ != PREVIEW_STARTED && preview_state_ != PREVIEW_STARTING) {
    return;
  }
  preview_state_ = PREVIEW_STOPPING;
  stop_preview_cb_ = std::move(cb);
}

void Camera3Service::Camera3DeviceService::StartAutoFocusOnServiceThread() {
  DCHECK(service_thread_.IsCurrentThread());
  uint8_t af_mode = ANDROID_CONTROL_AF_MODE_AUTO;
  EXPECT_EQ(0, UpdateMetadata(ANDROID_CONTROL_AF_MODE, &af_mode, 1,
                              &repeating_preview_metadata_));
  if (!oneshot_preview_metadata_.get()) {
    oneshot_preview_metadata_.reset(
        clone_camera_metadata(repeating_preview_metadata_.get()));
  }
  uint8_t af_trigger = ANDROID_CONTROL_AF_TRIGGER_START;
  EXPECT_EQ(0, UpdateMetadata(ANDROID_CONTROL_AF_TRIGGER, &af_trigger, 1,
                              &oneshot_preview_metadata_));
}

void Camera3Service::Camera3DeviceService::AddMetadataListenerOnServiceThread(
    int32_t key,
    std::unordered_set<int32_t> values,
    base::OnceCallback<void()> cb,
    int32_t* result) {
  DCHECK(service_thread_.IsCurrentThread());
  metadata_listener_list_.emplace_back(key, values, std::move(cb), result);
}

void Camera3Service::Camera3DeviceService::
    DeleteMetadataListenerOnServiceThread(int32_t key,
                                          std::unordered_set<int32_t> values) {
  DCHECK(service_thread_.IsCurrentThread());
  for (auto it = metadata_listener_list_.begin();
       it != metadata_listener_list_.end(); it++) {
    if (it->key == key && it->values == values) {
      it = metadata_listener_list_.erase(it);
      break;
    }
  }
}

void Camera3Service::Camera3DeviceService::LockAWBOnServiceThread() {
  DCHECK(service_thread_.IsCurrentThread());
  uint8_t awb_lock = ANDROID_CONTROL_AWB_LOCK_ON;
  EXPECT_EQ(0, UpdateMetadata(ANDROID_CONTROL_AWB_LOCK, &awb_lock, 1,
                              &repeating_preview_metadata_));
}

void Camera3Service::Camera3DeviceService::StartAEPrecaptureOnServiceThread() {
  DCHECK(service_thread_.IsCurrentThread());
  if (!oneshot_preview_metadata_.get()) {
    oneshot_preview_metadata_.reset(
        clone_camera_metadata(repeating_preview_metadata_.get()));
  }
  uint8_t ae_trigger = ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER_START;
  EXPECT_EQ(0, UpdateMetadata(ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
                              &ae_trigger, 1, &oneshot_preview_metadata_));
}

void Camera3Service::Camera3DeviceService::StartFaceDetectionOnServiceThread() {
  DCHECK(service_thread_.IsCurrentThread());
  uint8_t fd_mode = ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE;
  EXPECT_EQ(0, UpdateMetadata(ANDROID_STATISTICS_FACE_DETECT_MODE, &fd_mode, 1,
                              &repeating_preview_metadata_));
}

void Camera3Service::Camera3DeviceService::StopFaceDetectionOnServiceThread() {
  DCHECK(service_thread_.IsCurrentThread());
  uint8_t fd_mode = ANDROID_STATISTICS_FACE_DETECT_MODE_OFF;
  EXPECT_EQ(0, UpdateMetadata(ANDROID_STATISTICS_FACE_DETECT_MODE, &fd_mode, 1,
                              &repeating_preview_metadata_));
}

void Camera3Service::Camera3DeviceService::TakeStillCaptureOnServiceThread(
    const camera_metadata_t* metadata, base::OnceCallback<void()> cb) {
  DCHECK(service_thread_.IsCurrentThread());
  still_capture_metadata_ = metadata;
  still_capture_cb_ = std::move(cb);
}

void Camera3Service::Camera3DeviceService::StartRecordingOnServiceThread(
    const camera_metadata_t* metadata, base::OnceCallback<void(int)> cb) {
  DCHECK(service_thread_.IsCurrentThread());

  if (!metadata) {
    LOGF(ERROR) << "Invalid metadata settings";
    std::move(cb).Run(-EINVAL);
    return;
  }
  if (preview_state_ != PREVIEW_STARTED) {
    VLOGF(2) << "Preview is not started yet. Retrying...";
    usleep(500);
    service_thread_.PostTaskAsync(
        FROM_HERE,
        base::BindOnce(&Camera3Service::Camera3DeviceService::
                           StartRecordingOnServiceThread,
                       base::Unretained(this), metadata, std::move(cb)));
    return;
  }
  auto it = std::find_if(
      streams_.begin(), streams_.end(), [](const camera3_stream_t* stream) {
        return (stream->format == HAL_PIXEL_FORMAT_YCbCr_420_888);
      });
  if (it == streams_.end()) {
    ADD_FAILURE() << "Failed to find configured recording stream";
    std::move(cb).Run(-EINVAL);
    return;
  }
  const camera3_stream_t* record_stream = *it;

  for (uint32_t i = 0; i < number_of_capture_requests_; i++) {
    std::vector<const camera3_stream_t*> streams(1, record_stream);
    std::vector<camera3_stream_buffer_t> output_buffers;
    if (cam_device_.AllocateOutputBuffersByStreams(streams, &output_buffers) !=
        0) {
      ADD_FAILURE() << "Failed to allocate output buffer";
      std::move(cb).Run(-EINVAL);
      return;
    }
    output_stream_buffers_[i][kRecordingOutputStreamIdx] =
        output_buffers.front();
  }
  recording_metadata_ = metadata;
  std::move(cb).Run(0);
}

void Camera3Service::Camera3DeviceService::StopRecordingOnServiceThread(
    base::OnceCallback<void()> cb) {
  recording_metadata_ = nullptr;
  stop_recording_cb_ = std::move(cb);
}

void Camera3Service::Camera3DeviceService::
    ProcessPreviewRequestOnServiceThread() {
  DCHECK(service_thread_.IsCurrentThread());
  size_t capture_request_idx = 0;
  for (; capture_request_idx < capture_requests_.size();
       capture_request_idx++) {
    if (!capture_requests_[capture_request_idx].second) {
      break;
    }
  }
  ASSERT_NE(capture_request_idx, capture_requests_.size())
      << "Out of captures requests";
  capture_requests_[capture_request_idx].second = true;
  camera3_capture_request_t* request =
      &capture_requests_[capture_request_idx].first;
  // Initially there is preview stream only
  request->num_output_buffers = 1;
  if (recording_metadata_) {
    request->settings = recording_metadata_;
    ++request->num_output_buffers;
  }
  if (still_capture_metadata_) {
    auto it = std::find_if(streams_.begin(), streams_.end(),
                           [](const camera3_stream_t* stream) {
                             return (stream->format == HAL_PIXEL_FORMAT_BLOB);
                           });
    ASSERT_NE(streams_.end(), it)
        << "Failed to find configured still capture stream";
    const camera3_stream_t* still_capture_stream = *it;
    std::vector<const camera3_stream_t*> streams(1, still_capture_stream);
    std::vector<camera3_stream_buffer_t> output_buffers;
    ASSERT_EQ(
        0, cam_device_.AllocateOutputBuffersByStreams(streams, &output_buffers))
        << "Failed to allocate output buffer";
    request->settings = still_capture_metadata_;
    output_stream_buffers_[capture_request_idx][request->num_output_buffers] =
        output_buffers.front();
    ++request->num_output_buffers;
  }
  if (!recording_metadata_ && !still_capture_metadata_) {
    // Request with one-shot metadata if there is one
    request->settings = oneshot_preview_metadata_.get()
                            ? oneshot_preview_metadata_.get()
                            : repeating_preview_metadata_.get();
  }
  ASSERT_EQ(0, cam_device_.ProcessCaptureRequest(request))
      << "Failed to process capture request";
  ++number_of_in_flight_requests_;
  VLOGF(1) << "Capture request";
  VLOGF(1) << "  Frame " << request->frame_number;
  VLOGF(1) << "  Index " << capture_request_idx;
  for (size_t i = 0; i < request->num_output_buffers; i++) {
    VLOGF(1) << "  Buffer " << *request->output_buffers[i].buffer
             << " (format:" << request->output_buffers[i].stream->format << ","
             << request->output_buffers[i].stream->width << "x"
             << request->output_buffers[i].stream->height << ")";
  }
  VLOGF(1) << "  Settings " << request->settings;
  if (still_capture_metadata_) {
    still_capture_metadata_ = nullptr;
    std::move(still_capture_cb_).Run();
  } else if (!recording_metadata_ && !still_capture_metadata_ &&
             oneshot_preview_metadata_.get()) {
    oneshot_preview_metadata_.reset(nullptr);
  }
}

void Camera3Service::Camera3DeviceService::
    ProcessResultMetadataOutputBuffersOnServiceThread(
        uint32_t frame_number,
        ScopedCameraMetadata metadata,
        std::vector<cros::ScopedBufferHandle> buffers) {
  DCHECK(service_thread_.IsCurrentThread());
  --number_of_in_flight_requests_;
  size_t capture_request_idx = 0;
  for (; capture_request_idx < capture_requests_.size();
       capture_request_idx++) {
    if (capture_requests_[capture_request_idx].first.frame_number ==
        frame_number) {
      break;
    }
  }
  ASSERT_NE(capture_request_idx, capture_requests_.size())
      << "Failed to find frame " << frame_number << " in the requests";
  VLOGF(1) << "Capture result";
  VLOGF(1) << "  Frame " << frame_number;
  VLOGF(1) << "  Index " << capture_request_idx;
  // Process result metadata according to listeners
  for (auto it = metadata_listener_list_.begin();
       it != metadata_listener_list_.end();) {
    camera_metadata_ro_entry_t entry;
    if (find_camera_metadata_ro_entry(metadata.get(), it->key, &entry) == 0 &&
        it->values.find(entry.data.i32[0]) != it->values.end()) {
      VLOGF(1) << "Metadata listener gets tag "
               << get_camera_metadata_tag_name(it->key) << " value "
               << entry.data.i32[0];
      if (it->result) {
        *it->result = entry.data.i32[0];
      }
      std::move(it->cb).Run();
      it = metadata_listener_list_.erase(it);
    } else {
      it++;
    }
  }
  // Process output buffers and record perf logs. We record preview and video
  // perf logs only if there's no still capture in this result since it is
  // expected to take longer time.
  const bool has_still_capture = std::any_of(
      buffers.begin(), buffers.end(),
      [](const cros::ScopedBufferHandle& buffer) {
        return Camera3TestGralloc::GetFormat(*buffer) == HAL_PIXEL_FORMAT_BLOB;
      });
  const bool stopping_preview =
      (preview_state_ == PREVIEW_STOPPING) && !still_capture_metadata_;
  bool have_yuv_buffer = false;
  for (auto& it : buffers) {
    VLOGF(1) << "  Buffer " << *it
             << " (format:" << Camera3TestGralloc::GetFormat(*it) << ")";
    switch (Camera3TestGralloc::GetFormat(*it)) {
      case HAL_PIXEL_FORMAT_BLOB:
        Camera3PerfLog::GetInstance()->UpdateFrameEvent(
            cam_id_, frame_number, FrameEvent::STILL_CAPTURE_RESULT,
            base::TimeTicks::Now());
        if (!process_still_capture_result_cb_.is_null()) {
          process_still_capture_result_cb_.Run(
              cam_id_, frame_number, std::move(metadata), std::move(it));
        }
        break;
      case HAL_PIXEL_FORMAT_YCbCr_420_888:
        have_yuv_buffer = true;
        if (!has_still_capture) {
          Camera3PerfLog::GetInstance()->UpdateFrameEvent(
              cam_id_, frame_number, FrameEvent::VIDEO_RECORD_RESULT,
              base::TimeTicks::Now());
        }
        if (!process_recording_result_cb_.is_null()) {
          process_recording_result_cb_.Run(cam_id_, frame_number,
                                           std::move(metadata));
        }
        if (recording_metadata_ && !stopping_preview) {
          // Register buffer back to be used by future requests
          cam_device_.RegisterOutputBuffer(
              *output_stream_buffers_[capture_request_idx]
                                     [kRecordingOutputStreamIdx]
                                         .stream,
              std::move(it));
        }
        break;
      default:
        if (!process_preview_result_cb_.is_null()) {
          process_preview_result_cb_.Run(cam_id_, frame_number,
                                         std::move(metadata));
        }
        if (!has_still_capture) {
          Camera3PerfLog::GetInstance()->UpdateFrameEvent(
              cam_id_, frame_number, FrameEvent::PREVIEW_RESULT,
              base::TimeTicks::Now());
        }
        if (!stopping_preview) {
          // Register buffer back to be used by future requests
          cam_device_.RegisterOutputBuffer(
              *output_stream_buffers_[capture_request_idx]
                                     [kPreviewOutputStreamIdx]
                                         .stream,
              std::move(it));
        }
    }
  }
  if (preview_state_ == PREVIEW_STARTING) {
    preview_state_ = PREVIEW_STARTED;
    Camera3PerfLog::GetInstance()->UpdateDeviceEvent(
        cam_id_, DeviceEvent::PREVIEW_STARTED, base::TimeTicks::Now());
  }
  sem_post(&preview_frame_sem_);

  if (!stop_recording_cb_.is_null() && !have_yuv_buffer) {
    std::move(stop_recording_cb_).Run();
  }
  if (stopping_preview) {
    VLOGF(1) << "Stopping preview ... (" << number_of_in_flight_requests_
             << " requests in flight";
    if (number_of_in_flight_requests_ == 0) {
      preview_state_ = PREVIEW_STOPPED;
      if (!stop_preview_cb_.is_null()) {
        std::move(stop_preview_cb_).Run();
      }
    }
    return;
  }
  capture_requests_[capture_request_idx].second = false;
  ProcessPreviewRequestOnServiceThread();
}

}  // namespace camera3_test
