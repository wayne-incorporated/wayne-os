// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_CROS_CAMERA_MANAGER_H_
#define FACED_CAMERA_CROS_CAMERA_MANAGER_H_

#include <memory>

#include <absl/status/statusor.h>
#include <base/functional/callback_forward.h>
#include <base/memory/scoped_refptr.h>

#include "faced/camera/camera_client.h"
#include "faced/camera/camera_manager.h"
#include "faced/util/queueing_stream.h"

namespace faced {

// A CameraManager that connects to the system's CameraHAL service, and provides
// frames from the real system camera.
class CrosCameraManager final : public CameraManager {
 public:
  explicit CrosCameraManager(CameraClient& client,
                             const CameraClient::CaptureFramesConfig& config);
  ~CrosCameraManager() override;

  // `CameraManager` interface implementation.
  absl::StatusOr<std::unique_ptr<CameraStreamReader>> Open() override;
  void Close(base::OnceClosure close_complete) override;

 private:
  // Called when the camera has closed.
  void OnCameraClosed(absl::Status final_status);

  // The camera to manage, and its desired configuration.
  CameraClient& camera_;
  CameraClient::CaptureFramesConfig config_;

  // Current queue we are publishing frames to.
  std::optional<QueueingStream<absl::StatusOr<std::unique_ptr<Frame>>>> stream_;

  // Pending close callback. If set, we are attempting to shut down the camera.
  // This callback should be called once the close has completed.
  base::OnceClosure close_complete_;
};

}  // namespace faced

#endif  // FACED_CAMERA_CROS_CAMERA_MANAGER_H_
