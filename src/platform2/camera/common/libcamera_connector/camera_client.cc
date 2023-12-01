/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/libcamera_connector/camera_client.h"

#include <algorithm>
#include <cmath>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/flat_set.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/posix/safe_strerror.h>

#include "common/libcamera_connector/camera_metadata_utils.h"
#include "common/libcamera_connector/supported_formats.h"
#include "common/libcamera_connector/types.h"
#include "cros-camera/camera_service_connector.h"
#include "cros-camera/common.h"
#include "cros-camera/future.h"

namespace {

constexpr int32_t kDefaultFps = 30;

std::string GetCameraName(const cros::mojom::CameraInfoPtr& info) {
  switch (info->facing) {
    case cros::mojom::CameraFacing::CAMERA_FACING_BACK:
      return "Back Camera";
    case cros::mojom::CameraFacing::CAMERA_FACING_FRONT:
      return "Front Camera";
    case cros::mojom::CameraFacing::CAMERA_FACING_EXTERNAL:
      return "External Camera";
    default:
      return "Unknown Camera";
  }
}

int GetCameraFacing(const cros::mojom::CameraInfoPtr& info) {
  switch (info->facing) {
    case cros::mojom::CameraFacing::CAMERA_FACING_BACK:
      return CROS_CAM_FACING_BACK;
    case cros::mojom::CameraFacing::CAMERA_FACING_FRONT:
      return CROS_CAM_FACING_FRONT;
    case cros::mojom::CameraFacing::CAMERA_FACING_EXTERNAL:
      return CROS_CAM_FACING_EXTERNAL;
    default:
      LOGF(ERROR) << "unknown facing " << info->facing;
      return CROS_CAM_FACING_EXTERNAL;
  }
}

base::flat_set<int32_t> GetAvailableFramerates(
    const cros::mojom::CameraMetadataPtr& static_metadata) {
  base::flat_set<int32_t> candidates;
  auto available_fps_ranges = cros::GetMetadataEntryAsSpan<int32_t>(
      static_metadata, cros::mojom::CameraMetadataTag::
                           ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES);
  if (available_fps_ranges.empty()) {
    // If there is no available target fps ranges listed in metadata, we set a
    // default fps as candidate.
    LOGF(WARNING) << "No available fps ranges in metadata. Set default fps as "
                     "candidate.";
    candidates.insert(kDefaultFps);
    return candidates;
  }

  // The available target fps ranges are stored as pairs int32s: (min, max) x n.
  const size_t kRangeMaxOffset = 1;
  const size_t kRangeSize = 2;

  for (size_t i = 0; i < available_fps_ranges.size(); i += kRangeSize) {
    candidates.insert(available_fps_ranges[i + kRangeMaxOffset]);
  }
  return candidates;
}

}  // namespace

namespace cros {

CameraClient::CameraClient()
    : ipc_thread_("CamClientIpc"),
      info_thread_("CamClientInfo"),
      camera_hal_client_(this),
      camera_module_callbacks_(base::BindRepeating(
          &CameraClient::OnDeviceStatusChange, base::Unretained(this))),
      cam_info_callback_(nullptr) {}

void CameraClient::Init(RegisterClientCallback register_client_callback,
                        IntOnceCallback init_callback) {
  bool ret = ipc_thread_.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0));
  if (!ret) {
    LOGF(ERROR) << "Failed to start IPC thread";
    std::move(init_callback).Run(-ENODEV);
    return;
  }
  if (!info_thread_.Start()) {
    LOGF(ERROR) << "Failed to start camera info callback thread";
    std::move(init_callback).Run(-ENODEV);
    return;
  }
  init_callback_ = std::move(init_callback);
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraClient::RegisterClient, base::Unretained(this),
                     std::move(register_client_callback)));
}

int CameraClient::Exit() {
  auto future = cros::Future<int>::Create(nullptr);
  StopCurrentCapture(cros::GetFutureCallback(future));
  int ret = future->Get();
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraClient::ResetOnIpcThread, base::Unretained(this)));
  ipc_thread_.Stop();
  info_thread_.Stop();
  return ret;
}

int CameraClient::SetCameraInfoCallback(cros_cam_get_cam_info_cb_t callback,
                                        void* context) {
  base::AutoLock l(camera_info_lock_);

  cam_info_callback_ = callback;
  cam_info_context_ = context;
  SendCameraInfo(camera_id_set_, /*is_removed=*/0);
  return 0;
}

int CameraClient::StartCapture(const cros_cam_capture_request_t* request,
                               cros_cam_capture_cb_t callback,
                               void* context) {
  auto future = cros::Future<int>::Create(nullptr);
  SessionRequest session_request = {
      .type = SessionRequestType::kStart,
      .info = {.camera_id = request->id,
               .format = *request->format,
               .capture_callback = callback,
               .context = context},
      .result_callback = cros::GetFutureCallback(future)};
  PushSessionRequest(std::move(session_request));
  return future->Get();
}

int CameraClient::StopCapture(int id) {
  auto future = cros::Future<int>::Create(nullptr);
  SessionRequest session_request = {
      .type = SessionRequestType::kStop,
      .info = {.camera_id = id},
      .result_callback = cros::GetFutureCallback(future)};
  PushSessionRequest(std::move(session_request));
  return future->Get();
}

void CameraClient::SetUpChannel(
    mojo::PendingRemote<mojom::CameraModule> camera_module) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  LOGF(INFO) << "Received camera module from camera HAL dispatcher";
  camera_module_.Bind(std::move(camera_module));
  camera_module_.set_disconnect_handler(
      base::BindOnce(&CameraClient::ResetClientState, base::Unretained(this)));

  GetAllCameraInfo();
}

void CameraClient::RegisterClient(
    RegisterClientCallback register_client_callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  std::move(register_client_callback)
      .Run(camera_hal_client_.BindNewPipeAndPassRemote(),
           base::BindOnce(&CameraClient::OnRegisteredClient,
                          base::Unretained(this)));
}

void CameraClient::OnRegisteredClient(int32_t result) {
  if (result != 0) {
    LOGF(ERROR) << "Failed to register client: "
                << base::safe_strerror(-result);
    std::move(init_callback_).Run(result);
  }
  LOGF(INFO) << "Successfully registered client";
}

void CameraClient::ResetOnIpcThread() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  camera_hal_client_.reset();
}

void CameraClient::ResetClientState() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(camera_info_lock_);

  LOGF(WARNING) << "Mojo connection to HAL server disconnected";
  camera_module_.reset();
  // Notify the user that cameras are down.
  SendCameraInfoAsync(camera_id_set_, /*is_removed=*/1);
  camera_id_set_.clear();
  camera_info_map_.clear();
  pending_camera_id_set_ = {};
  processing_camera_id_set_.clear();
  if (init_callback_) {
    // If mojo disconnects during initialization, we can wait for the mojo
    // connection to come back and re-do the initialization. In addition, We
    // wouldn't have a valid session context here. Hence we don't reset sessions
    // or CameraClientOps.
    return;
  }
  switch (context_.state) {
    case SessionState::kIdle: {
      // No need to do anything.
      break;
    }
    case SessionState::kStarting: {
      std::move(context_.result_callback).Run(-ENODEV);
      break;
    }
    case SessionState::kCapturing: {
      cros_cam_capture_result_t result = {.status = -ENODEV, .frame = nullptr};
      (*context_.info.capture_callback)(context_.info.context, &result);
      break;
    }
    case SessionState::kStopping: {
      std::move(context_.result_callback).Run(-ENODEV);
      break;
    }
  }
  context_.state = SessionState::kIdle;
  FlushInflightSessionRequests(-ENODEV);
  context_.client_ops.Reset();
}

void CameraClient::GetAllCameraInfo() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  camera_module_->GetNumberOfCameras(base::BindOnce(
      &CameraClient::OnGotNumberOfCameras, base::Unretained(this)));
}

void CameraClient::OnGotNumberOfCameras(int32_t num_builtin_cameras) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(camera_info_lock_);

  LOGF(INFO) << "Number of builtin cameras: " << num_builtin_cameras;

  for (int32_t i = 0; i < num_builtin_cameras; ++i) {
    pending_camera_id_set_.insert(i);
  }
  SetCallbacks();
}

void CameraClient::SetCallbacks() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  camera_module_->SetCallbacksAssociated(
      camera_module_callbacks_.GetModuleCallbacks(),
      base::BindOnce(&CameraClient::OnSetCallbacks, base::Unretained(this)));
}

void CameraClient::OnSetCallbacks(int32_t result) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (result != 0) {
    LOGF(ERROR) << "Failed to set callbacks" << base::safe_strerror(-result);
    if (init_callback_) {
      std::move(init_callback_).Run(-ENODEV);
    }
    return;
  }
  // After SetCallbacks(), it is guaranteed that all present cameras are probed.
  size_t num_cameras = pending_camera_id_set_.size() +
                       processing_camera_id_set_.size() + camera_id_set_.size();
  if (num_cameras == 0) {
    LOGF(WARNING) << "No built-in or connected cameras found";
    if (init_callback_) {
      context_.state = SessionState::kIdle;
      std::move(init_callback_).Run(0);
    }
    return;
  }
  GetCameraInfo();
}

void CameraClient::GetCameraInfo() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  for (auto it = pending_camera_id_set_.begin();
       it != pending_camera_id_set_.end();) {
    int32_t camera_id = *it;
    it = pending_camera_id_set_.erase(it);
    processing_camera_id_set_.insert(camera_id);
    camera_module_->GetCameraInfo(
        camera_id, base::BindOnce(&CameraClient::OnGotCameraInfo,
                                  base::Unretained(this), camera_id));
  }
}

void CameraClient::OnGotCameraInfo(int32_t camera_id,
                                   int32_t result,
                                   mojom::CameraInfoPtr info) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(camera_info_lock_);

  if (result != 0) {
    LOGF(ERROR) << "Failed to get camera info of " << camera_id << ": "
                << base::safe_strerror(-result);
    processing_camera_id_set_.erase(camera_id);
    if (init_callback_) {
      std::move(init_callback_).Run(-ENODEV);
    }
    return;
  }

  LOGF(INFO) << "Gotten camera info of " << camera_id;
  device_api_version_ = info->device_version;

  auto& camera_info = camera_info_map_[camera_id];
  camera_info.facing = GetCameraFacing(info);
  camera_info.name = GetCameraName(info);

  auto& format_info = camera_info_map_[camera_id].format_info;
  auto candidate_fps_set =
      GetAvailableFramerates(info->static_camera_characteristics);
  auto min_frame_durations = GetMetadataEntryAsSpan<int64_t>(
      info->static_camera_characteristics,
      mojom::CameraMetadataTag::ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS);
  for (size_t i = 0; i < min_frame_durations.size(); i += 4) {
    int64_t hal_pixel_format = min_frame_durations[i + 0];
    int64_t width = min_frame_durations[i + 1];
    int64_t height = min_frame_durations[i + 2];
    int64_t duration_ns = min_frame_durations[i + 3];

    uint32_t fourcc = GetV4L2PixelFormat(hal_pixel_format);
    if (fourcc == 0) {
      VLOGF(1) << "Skip unsupported format " << hal_pixel_format;
      continue;
    }

    int max_fps = 1e9 / duration_ns;
    for (auto fps : candidate_fps_set) {
      if (fps > max_fps) {
        continue;
      }
      cros_cam_format_info_t info = {.fourcc = fourcc,
                                     .width = static_cast<int>(width),
                                     .height = static_cast<int>(height),
                                     .fps = fps};

      format_info.push_back(std::move(info));
    }
  }

  camera_info.jpeg_max_size = GetMetadataEntryAsSpan<int32_t>(
      info->static_camera_characteristics,
      mojom::CameraMetadataTag::ANDROID_JPEG_MAX_SIZE)[0];

  camera_id_set_.insert(camera_id);
  processing_camera_id_set_.erase(camera_id);

  if (init_callback_) {
    if (processing_camera_id_set_.empty()) {
      // TODO(lnishan): Initialize all states when multi-device streaming is
      // supported.
      context_.state = SessionState::kIdle;
      std::move(init_callback_).Run(0);
    }
  } else if (cam_info_callback_) {
    SendCameraInfoAsync({camera_id}, /*is_removed=*/0);
  }
}

void CameraClient::SendCameraInfo(const std::set<int32_t>& camera_id_set,
                                  int is_removed) {
  camera_info_lock_.AssertAcquired();

  for (auto& camera_id : camera_id_set) {
    GenerateAndSendCameraInfo(camera_id, is_removed);
  }
}

void CameraClient::SendCameraInfoAsync(const std::set<int32_t>& camera_id_set,
                                       int is_removed) {
  info_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraClient::SendCameraInfoAsyncOnInfoThread,
                     base::Unretained(this), camera_id_set, is_removed));
}

void CameraClient::SendCameraInfoAsyncOnInfoThread(
    std::set<int32_t> camera_id_set, int is_removed) {
  DCHECK(info_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(camera_info_lock_);

  for (auto& camera_id : camera_id_set) {
    GenerateAndSendCameraInfo(camera_id, is_removed);
  }
}

void CameraClient::GenerateAndSendCameraInfo(int32_t camera_id,
                                             int is_removed) {
  camera_info_lock_.AssertAcquired();

  // Generate camera info
  cros_cam_info_t cam_info;
  if (is_removed) {
    cam_info = {.id = camera_id};
  } else {
    auto it = camera_info_map_.find(camera_id);
    if (it == camera_info_map_.end()) {
      LOGF(ERROR) << "Cannot find the info of camera " << camera_id;
      return;
    }
    auto& camera_info = it->second;
    cam_info = {
        .id = camera_id,
        .facing = camera_info.facing,
        .name = camera_info.name.c_str(),
        .format_count = static_cast<int>(camera_info.format_info.size()),
        .format_info = camera_info.format_info.data()};
  }

  // Send camera info
  if (cam_info_callback_ == nullptr) {
    return;
  }
  int ret = (*cam_info_callback_)(cam_info_context_, &cam_info, is_removed);
  if (ret != 0) {
    // Deregister callback
    cam_info_callback_ = nullptr;
    cam_info_context_ = nullptr;
  }
}

void CameraClient::PushSessionRequest(SessionRequest request) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraClient::PushSessionRequestOnIpcThread,
                                base::Unretained(this), std::move(request)));
}

void CameraClient::PushSessionRequestOnIpcThread(SessionRequest request) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  pending_session_requests_.push(std::move(request));
  TryProcessSessionRequests();
}

void CameraClient::TryProcessSessionRequests() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  while (!pending_session_requests_.empty() &&
         ProcessSessionRequest(&pending_session_requests_.front()) == 0) {
    pending_session_requests_.pop();
  }
}

int CameraClient::ProcessSessionRequest(SessionRequest* request) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  switch (request->type) {
    case SessionRequestType::kStart:
      return StartCaptureOnIpcThread(request);
    case SessionRequestType::kStop:
      return StopCaptureOnIpcThread(request);
    default:
      LOGF(ERROR) << "Unexpected session request type";
      std::move(request->result_callback).Run(-EINVAL);
      return 0;
  }
}

void CameraClient::FlushInflightSessionRequests(int error) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  while (!pending_session_requests_.empty()) {
    auto request = std::move(pending_session_requests_.front());
    pending_session_requests_.pop();
    std::move(request.result_callback).Run(error);
  }
}

int CameraClient::StartCaptureOnIpcThread(SessionRequest* request) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (!IsDeviceActive(request->info.camera_id)) {
    LOGF(ERROR) << "Cannot start capture on an inactive device: "
                << request->info.camera_id;
    std::move(request->result_callback).Run(-ENODEV);
    return 0;
  }

  // TODO(lnishan): Support multi-device streaming by checking against the state
  // of the specified device only.
  switch (context_.state) {
    case SessionState::kIdle:
      // Proceed to start capture.
      break;
    case SessionState::kStarting:
      LOGF(WARNING) << "Capture is already starting";
      std::move(request->result_callback).Run(-EIO);
      return 0;
    case SessionState::kCapturing:
      LOGF(WARNING) << "Capture is already started";
      std::move(request->result_callback).Run(-EIO);
      return 0;
    case SessionState::kStopping:
      // Cannot start capture when the device is still being closed.
      return -EAGAIN;
  }

  LOGF(INFO) << "Starting capture";
  context_.state = SessionState::kStarting;
  context_.info = std::move(request->info);
  context_.result_callback = std::move(request->result_callback);
  auto device_ops_receiver = context_.client_ops.Init(
      device_api_version_, base::BindRepeating(&CameraClient::SendCaptureResult,
                                               base::Unretained(this)));
  camera_module_->OpenDevice(
      context_.info.camera_id, std::move(device_ops_receiver),
      base::BindOnce(&CameraClient::OnOpenedDevice, base::Unretained(this)));
  return 0;
}

void CameraClient::OnOpenedDevice(int32_t result) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  CHECK_EQ(context_.state, SessionState::kStarting);

  const auto& info = context_.info;
  if (result != 0) {
    LOGF(ERROR) << "Failed to open camera " << info.camera_id << ": "
                << base::safe_strerror(-result);
    context_.state = SessionState::kIdle;
  } else {
    base::AutoLock l(camera_info_lock_);
    LOGF(INFO) << "Camera opened successfully";
    context_.state = SessionState::kCapturing;
    context_.client_ops.StartCapture(
        info.camera_id, &info.format,
        camera_info_map_[info.camera_id].jpeg_max_size);
  }
  std::move(context_.result_callback).Run(result);

  TryProcessSessionRequests();
}

int CameraClient::StopCaptureOnIpcThread(SessionRequest* request) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (!IsDeviceActive(request->info.camera_id)) {
    LOGF(ERROR) << "Cannot stop capture on an inactive device: "
                << request->info.camera_id;
    std::move(request->result_callback).Run(-ENODEV);
    return 0;
  }

  // TODO(lnishan): Support multi-device streaming.
  CHECK_EQ(request->info.camera_id, context_.info.camera_id);

  // TODO(lnishan): Support multi-device streaming by checking against the state
  // of the specified device only.
  switch (context_.state) {
    case SessionState::kIdle:
      LOGF(WARNING) << "Capture is already stopped";
      std::move(request->result_callback).Run(-EIO);
      return 0;
    case SessionState::kStarting:
      return -EAGAIN;
    case SessionState::kCapturing:
      // Proceed to close the camera.
      break;
    case SessionState::kStopping:
      LOGF(WARNING) << "Capture is already stopping";
      std::move(request->result_callback).Run(-EIO);
      return 0;
  }

  LOGF(INFO) << "Stopping capture";
  context_.state = SessionState::kStopping;
  context_.result_callback = std::move(request->result_callback);
  context_.client_ops.StopCapture(
      base::BindOnce(&CameraClient::OnClosedDevice, base::Unretained(this)));
  return 0;
}

void CameraClient::OnClosedDevice(int32_t result) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  CHECK_EQ(context_.state, SessionState::kStopping);

  if (result != 0) {
    LOGF(ERROR) << "Failed to close camera " << context_.info.camera_id << ": "
                << base::safe_strerror(-result);
  } else {
    LOGF(INFO) << "Camera closed successfully";
  }

  // We transition the state to |SessionState::kIdle| here regardless of the
  // result to allow further retries. It's also possible that a device is
  // disconnected while the device is closing, and such an event would be
  // recoverable.
  context_.state = SessionState::kIdle;
  std::move(context_.result_callback).Run(result);

  TryProcessSessionRequests();
}

bool CameraClient::IsDeviceActive(int device) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(camera_info_lock_);

  return camera_info_map_.find(device) != camera_info_map_.end();
}

void CameraClient::OnDeviceStatusChange(int32_t camera_id, bool is_present) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  LOGF(INFO) << camera_id << " is " << (is_present ? "present" : "absent");
  if (is_present) {
    pending_camera_id_set_.insert(camera_id);
    GetCameraInfo();
  } else {
    camera_id_set_.erase(camera_id);
    camera_info_map_.erase(camera_id);
    SendCameraInfoAsync({camera_id}, /*is_removed=*/1);
  }
}

void CameraClient::SendCaptureResult(const cros_cam_capture_result_t& result) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  // Only permissible states here are |SessionState::kCapturing| and
  // |SessionState::kStopping|.
  switch (context_.state) {
    case SessionState::kIdle:
      LOGF(ERROR) << "Received a capture result while the device is idle";
      return;
    case SessionState::kStarting:
      LOGF(ERROR) << "Received a capture result while the capture is starting";
      return;
    case SessionState::kCapturing:
      break;
    case SessionState::kStopping:
      // We don't return any capture results if the capture is stopping.
      return;
  }

  int ret = (*context_.info.capture_callback)(context_.info.context, &result);
  // We don't need to do anything if the session is already stopping.
  if (context_.state == SessionState::kStopping) {
    return;
  }
  if (ret != 0 || result.status == -ENODEV) {
    CHECK_EQ(context_.state, SessionState::kCapturing);
    // Flush all inflight session requests to stop the capture immediately.
    FlushInflightSessionRequests(-EIO);
    SessionRequest request = {.type = SessionRequestType::kStop,
                              .info = context_.info,
                              .result_callback = base::BindOnce(
                                  &CameraClient::OnStoppedCaptureFromCallback,
                                  base::Unretained(this))};
    PushSessionRequestOnIpcThread(std::move(request));
    CHECK_EQ(context_.state, SessionState::kStopping);
  }
}

void CameraClient::OnStoppedCaptureFromCallback(int result) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (result != 0) {
    LOGF(ERROR) << "Failed to stop capture from capture callback";
  }
}

void CameraClient::StopCurrentCapture(IntOnceCallback callback) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraClient::StopCurrentCaptureOnIpcThread,
                                base::Unretained(this), std::move(callback)));
}

void CameraClient::StopCurrentCaptureOnIpcThread(IntOnceCallback callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  // Flush all inflight session requests to stop the capture immediately.
  FlushInflightSessionRequests(-EIO);

  if (context_.state == SessionState::kStopping ||
      context_.state == SessionState::kIdle) {
    // No need to stop capturing if there's no ongoing capture session or it's
    // already being stopped.
    std::move(callback).Run(0);
    return;
  }
  // TODO(lnishan): Stopping capture would fail here if the current state is
  // |SessionState::kStarting|. Handle that situation properly.
  SessionRequest request = {.type = SessionRequestType::kStop,
                            .info = context_.info,
                            .result_callback = std::move(callback)};
  PushSessionRequestOnIpcThread(std::move(request));
}

}  // namespace cros
