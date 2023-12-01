// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/fake_camera_client.h"

#include <memory>
#include <utility>
#include <vector>

#include <absl/status/status.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <cros-camera/camera_service_connector.h>
#include <linux/videodev2.h>

#include "faced/camera/camera_client.h"
#include "faced/camera/frame.h"
#include "faced/util/blocking_future.h"
#include "faced/util/task.h"

namespace faced::testing {

FakeCameraClient::FakeCameraClient() {
  // Set up a simple 1920x1080 YUV camera.
  device_ = CameraClient::DeviceInfo{
      .id = 0,
      .name = "Fake Camera",
      .formats = {cros_cam_format_info_t{
          .fourcc = V4L2_PIX_FMT_NV12,
          .width = 1920,
          .height = 1080,
          .fps = 30,
      }},
  };
}

FakeCameraClient::FakeCameraClient(DeviceInfo device) : device_(device) {}

CameraClient::CaptureFramesConfig FakeCameraClient::DefaultConfig() const {
  CHECK(!device_.formats.empty()) << "Fake device has no supported formats.";
  return CaptureFramesConfig{
      .camera_id = device_.id,
      .format = device_.formats[0],
  };
}

bool FakeCameraClient::Capturing() const {
  return frame_processor_ != nullptr;
}

void FakeCameraClient::WriteFrame(
    Frame frame, base::OnceCallback<void(absl::Status)> frame_done) {
  // Ensure a capture is in progress.
  if (frame_processor_ == nullptr) {
    PostToCurrentSequence(base::BindOnce(
        std::move(frame_done),
        absl::FailedPreconditionError("No capture in process.")));
    return;
  }

  // Drop the frame if one is already in flight.
  if (frame_in_flight_) {
    PostToCurrentSequence(base::BindOnce(
        std::move(frame_done),
        absl::UnavailableError("Frame already being processed.")));
    return;
  }

  // Set up clean up required after the frame has been processed.
  frame_in_flight_ = true;
  FrameProcessor::ProcessFrameDoneCallback done =
      base::BindOnce(&FakeCameraClient::WriteFrameComplete,
                     base::Unretained(this), std::move(frame_done));

  // Process the frame.
  PostToCurrentSequence(base::BindOnce(
      &FrameProcessor::ProcessFrame, frame_processor_,
      std::make_unique<Frame>(std::move(frame)), std::move(done)));
}

absl::Status FakeCameraClient::WriteFrameAndWait(Frame frame) {
  BlockingFuture<absl::Status> future;
  WriteFrame(std::move(frame), future.PromiseCallback());
  return future.Wait();
}

void FakeCameraClient::WriteFrameComplete(
    base::OnceCallback<void(absl::Status)> done,
    std::optional<absl::Status> status) {
  CHECK(frame_in_flight_)
      << "FakeCameraClient::WriteFrameComplete callback called when "
         "no frame was in flight.";
  frame_in_flight_ = false;

  // Notify the caller of `WriteFrame` the frame has been processed.
  PostToCurrentSequence(base::BindOnce(std::move(done), absl::OkStatus()));

  // If an error was given by the process frame callback, stop the camera, and
  // notify the caller.
  if (status.has_value()) {
    frame_processor_.reset();
    PostToCurrentSequence(
        base::BindOnce(std::move(capture_complete_), *status));
  }
}

void FakeCameraClient::CaptureFrames(
    const CaptureFramesConfig& config,
    const scoped_refptr<FrameProcessor>& frame_processor,
    StopCaptureCallback capture_complete) {
  capture_complete_ = std::move(capture_complete);
  frame_processor_ = frame_processor;
}

absl::StatusOr<std::vector<CameraClient::DeviceInfo>>
FakeCameraClient::GetDevices() {
  return std::vector<CameraClient::DeviceInfo>({device_});
}

absl::StatusOr<CameraClient::DeviceInfo> FakeCameraClient::GetDevice(int id) {
  if (id != 0) {
    return absl::NotFoundError("No such device.");
  }
  return device_;
}

}  // namespace faced::testing
