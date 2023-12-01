// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_FAKE_CAMERA_CLIENT_H_
#define FACED_CAMERA_FAKE_CAMERA_CLIENT_H_

#include <utility>
#include <vector>

#include <absl/status/status.h>
#include <base/functional/callback_forward.h>
#include <base/memory/scoped_refptr.h>

#include "faced/camera/camera_client.h"
#include "faced/camera/frame.h"

namespace faced::testing {

// A simulated CameraClient, allowing tests to publish individual frames.
class FakeCameraClient : public CameraClient {
 public:
  // Create a FakeCameraClient that simulates a camera with a simple example
  // configuration.
  FakeCameraClient();

  // Create a FakeCameraClient that simulates the given device.
  explicit FakeCameraClient(DeviceInfo device);

  // Return a CameraClient::CaptureFramesConfig supported by this fake camera.
  CaptureFramesConfig DefaultConfig() const;

  // Returns true if a capture is in progress.
  bool Capturing() const;

  // Write a frame to the current capture.
  //
  // The callback will be called when the frame has finished being processed.
  void WriteFrame(Frame frame,
                  base::OnceCallback<void(absl::Status)> frame_done);

  // Write a frame to the current capture, blocking until it is complete.
  absl::Status WriteFrameAndWait(Frame frame);

  // `CameraClient` implementation.
  void CaptureFrames(const CaptureFramesConfig& config,
                     const scoped_refptr<FrameProcessor>& frame_processor,
                     StopCaptureCallback capture_complete) override;
  absl::StatusOr<std::vector<DeviceInfo>> GetDevices() override;
  absl::StatusOr<DeviceInfo> GetDevice(int id) override;

 private:
  // Complete a `WriteFrame` operation after a frame has been processed.
  void WriteFrameComplete(base::OnceCallback<void(absl::Status)> done,
                          std::optional<absl::Status> status);

  // The simulated device.
  DeviceInfo device_;

  // Completion callback, called when capture stops.
  StopCaptureCallback capture_complete_;

  // The current frame processor, or nullptr if no capture is in progress.
  scoped_refptr<FrameProcessor> frame_processor_;

  // Set when a frame is currently being processed by `frame_processor_`.
  bool frame_in_flight_ = false;
};

}  // namespace faced::testing

#endif  // FACED_CAMERA_FAKE_CAMERA_CLIENT_H_
