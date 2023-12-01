// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/camera_client.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <absl/strings/str_format.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <linux/videodev2.h>

#include "faced/camera/camera_service.h"
#include "faced/camera/frame.h"
#include "faced/camera/frame_utils.h"
#include "faced/util/status.h"

namespace faced {

namespace {

// Convert the data in the given `cros_cam_info_t` struct into a
// `CameraClient::DeviceInfo` type.
CameraClient::DeviceInfo ToDeviceInfo(const cros_cam_info_t& info) {
  CameraClient::DeviceInfo result;
  result.id = info.id;
  result.name = std::string(info.name);
  for (int i = 0; i < info.format_count; i++) {
    result.formats.push_back(info.format_info[i]);
  }
  return result;
}

}  // namespace

std::string FourccToString(uint32_t fourcc) {
  uint32_t fourcc_processing = fourcc;
  std::string result;
  for (size_t i = 0; i < 4; i++, fourcc_processing >>= 8) {
    const char c = static_cast<char>(fourcc_processing & 0xFF);

    // If any character in the code is non-printable, don't attempt to decode
    // any of it, but just return the entire code as a hex string.
    if (!std::isprint(c)) {
      return base::StringPrintf("0x%08x", fourcc);
    }
    result.push_back(c);
  }
  return result;
}

bool IsFormatEqual(const cros_cam_format_info_t& fmt1,
                   const cros_cam_format_info_t& fmt2) {
  return fmt1.fourcc == fmt2.fourcc && fmt1.width == fmt2.width &&
         fmt1.height == fmt2.height && fmt1.fps == fmt2.fps;
}

absl::StatusOr<std::unique_ptr<CrosCameraClient>> CrosCameraClient::Create(
    std::unique_ptr<CameraService> camera_service) {
  // Establishes a connection with the cros camera service
  if (camera_service->Init() != 0) {
    return absl::UnavailableError("Failed to initialise camera client");
  }

  // Create the camera.
  return base::WrapUnique(new CrosCameraClient(std::move(camera_service)));
}

absl::StatusOr<std::vector<CameraClient::DeviceInfo>>
CrosCameraClient::GetDevices() {
  std::vector<CameraClient::DeviceInfo> result;

  // Enumerate all the cameras, and record them in `result`.
  //
  // `GetDeviceInfo` takes a callback that is called in two phases:
  //
  // 1. An initial, synchronous phase, where the callback is called once
  //    per camera;
  //
  // 2. A further, asynchronous phase, where the callback may be called
  //    at arbitrary points to provide updated information about changes
  //    to camera in the system.
  //
  // We don't attempt to provide support for updates, so we simply wait
  // for all the synchronous callbacks to occur, and then unregister
  // our callback.
  //
  // Additionally, because the callback is a C-style callback (i.e., a pure
  // function pointer and with a void* parameter), we can't just use a lambda
  // containing any captures, but instead pass through a pointer to `result`.
  int error_code = camera_service_->GetCameraInfo(
      [](void* context, const cros_cam_info_t* info, int is_removed) -> int {
        auto* result =
            static_cast<std::vector<CameraClient::DeviceInfo>*>(context);
        result->push_back(ToDeviceInfo(*info));
        return 0;
      },
      &result);
  if (error_code != 0) {
    return absl::UnknownError(base::StringPrintf(
        "Unable to fetch device camera information (status code %d).",
        error_code));
  }

  // Register with a no-op callback, ignoring any errors.
  (void)camera_service_->GetCameraInfo(
      [](void* context, const cros_cam_info_t* info, int is_removed) {
        return 1;
      },
      nullptr);

  return {std::move(result)};
}

absl::StatusOr<CameraClient::DeviceInfo> CrosCameraClient::GetDevice(int id) {
  // Search through the devices to find the requested device.
  //
  // The underlying API doesn't give us a way to access a particular device,
  // so we simply ask for all of them and then pull out the requested device.
  FACE_ASSIGN_OR_RETURN(std::vector<CameraClient::DeviceInfo> devices,
                        GetDevices());
  for (const CameraClient::DeviceInfo& device : devices) {
    if (device.id == id) {
      return device;
    }
  }

  return absl::NotFoundError(
      base::StringPrintf("Camera device with id %d not found.", id));
}

void CrosCameraClient::CaptureFrames(
    const CaptureFramesConfig& config,
    const scoped_refptr<FrameProcessor>& frame_processor,
    StopCaptureCallback capture_complete) {
  camera_id_ = config.camera_id;
  // Perform a copy since cros_cam_capture_request_t::format needs to be
  // non-const.
  format_ = config.format;

  // Create a cancelable callback which can be cancelled to stop any future
  // frames from being processed
  process_frame_callback_.Reset(
      base::BindRepeating(&FrameProcessor::ProcessFrame, frame_processor));

  capture_complete_ = std::move(capture_complete);

  LOG(INFO) << "Starting capture: device = " << config.camera_id
            << ", fourcc = " << FourccToString(config.format.fourcc)
            << ", width = " << config.format.width
            << ", height = " << config.format.height
            << ", fps = " << config.format.fps;

  // Start the capture.
  const cros_cam_capture_request_t request = {
      .id = camera_id_,
      .format = &format_,
  };

  int ret = camera_service_->StartCapture(
      &request, &CrosCameraClient::OnCaptureResultAvailable, this);
  if (ret != 0) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(capture_complete_),
                       absl::InternalError("Failed to start capture")));
    return;
  }
}

int CrosCameraClient::OnCaptureResultAvailable(
    void* context, const cros_cam_capture_result_t* result) {
  auto* client = reinterpret_cast<CrosCameraClient*>(context);

  if (result->status != 0) {
    LOG(ERROR) << "Received an error notification: "
               << base::safe_strerror(-result->status);
    return 0;
  }
  const cros_cam_frame_t* frame = result->frame;
  CHECK_NE(frame, nullptr);

  base::RepeatingCallback<void(std::unique_ptr<Frame>,
                               FrameProcessor::ProcessFrameDoneCallback)>
      callback = client->process_frame_callback_.callback();

  // If callback has been cancelled, then return -1 to inform the CameraHAL to
  // stop capturing.
  if (callback.is_null()) {
    client->task_runner_->PostTask(
        FROM_HERE, base::BindOnce(std::move(client->capture_complete_),
                                  client->completion_status_));
    return -1;
  }

  // Continue if callback exists.
  if (client->pending_request_) {
    LOG(WARNING) << "Frame dropped since there is already an in-flight frame "
                    "process request.";
    return 0;
  }

  client->pending_request_ = true;
  client->task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(callback, FrameFromCrosFrame(*frame),
                     base::BindOnce(&CrosCameraClient::CompletedProcessFrame,
                                    base::Unretained(client))));
  return 0;
}

void CrosCameraClient::CompletedProcessFrame(
    std::optional<absl::Status> opt_status) {
  if (opt_status.has_value()) {
    LOG(INFO) << "Stopping capture on camera: " << camera_id_;
    // Cancel the callback which will result in OnCaptureResultAvailable() to
    // return -1, informing the CameraHAL to stop capturing any more frames.
    // Note that we require one additional frame from the CameraHAL in order
    // to stop the CameraHAL capture and complete the CaptureFrames() call
    process_frame_callback_.Cancel();
    completion_status_ = opt_status.value();
  }

  pending_request_ = false;
}

std::optional<CameraClient::CaptureFramesConfig> GetHighestResolutionFormat(
    const CrosCameraClient::DeviceInfo& device,
    std::function<bool(const cros_cam_format_info_t&)> predicate) {
  std::optional<CrosCameraClient::CaptureFramesConfig> result;
  std::optional<int> best_resolution = 0;

  // Enumerate all devices and resolutions.
  for (const cros_cam_format_info_t& info : device.formats) {
    // Ignore resolutions that are strictly worse than something we have
    // already found.
    int current_resolution = info.height * info.width;
    if (best_resolution.has_value() && current_resolution < *best_resolution) {
      continue;
    }

    // Ignore unsupported devices or formats.
    if (!predicate(info)) {
      continue;
    }

    // We found a candidate.
    best_resolution = current_resolution;
    result = CameraClient::CaptureFramesConfig{
        .camera_id = device.id,
        .format = info,
    };
  }

  return result;
}

}  // namespace faced
