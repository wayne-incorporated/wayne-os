// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_FAKE_CAMERA_SERVICE_H_
#define FACED_CAMERA_FAKE_CAMERA_SERVICE_H_

#include <deque>
#include <string>
#include <vector>

#include <base/synchronization/lock.h>
#include <base/task/thread_pool.h>
#include <base/thread_annotations.h>

#include "faced/camera/camera_service.h"

namespace faced::testing {

// FakeCameraService provides fake data for tests
class FakeCameraService : public CameraService {
 public:
  FakeCameraService();
  ~FakeCameraService() override;

  // Disallow copy and move.
  FakeCameraService(const FakeCameraService&) = delete;
  FakeCameraService operator=(const FakeCameraService&) = delete;

  // Helper function to add test camera infos
  void AddCameraInfo(cros_cam_info_t cam_info, bool is_removed);

  // Helper function to add test results
  void AddResult(cros_cam_capture_result_t result);

  // Init set to always return success
  int Init() override;

  // Exit set to always return success
  int Exit() override;

  // Calls callback to all cameras that have been added via AddCameraInfo
  int GetCameraInfo(cros_cam_get_cam_info_cb_t callback,
                    void* context) override;

  // Starts capturing with the given parameters using a sequenced task runner
  int StartCapture(const cros_cam_capture_request_t* request,
                   cros_cam_capture_cb_t callback,
                   void* context) override;

  // Clears all results.
  int StopCapture(int id) override;

 private:
  // Send the next frame to our client.
  void DispatchNextFrame(const cros_cam_capture_request_t* request,
                         cros_cam_capture_cb_t callback,
                         void* context);

  base::Lock mutex_;

  // Current state of the camera service.
  enum class State {
    kCreated,    // Created, but Init() not yet called.
    kIdle,       // Ready to capture.
    kCapturing,  // Actively capturing
    kExit,       // Exit() called. The instance cannot be used again.
  };
  State state_ GUARDED_BY(mutex_) = State::kCreated;

  // Data for tests
  std::vector<cros_cam_info_t> camera_infos_ GUARDED_BY(mutex_);
  std::vector<bool> camera_is_removed_ GUARDED_BY(mutex_);
  std::deque<cros_cam_capture_result_t> results_ GUARDED_BY(mutex_);

  // The ID of the camera currently being captured from.
  int camera_id_ GUARDED_BY(mutex_) = -1;

  // Runner for calling the user's capture callback on.
  //
  // The real camera service calls the callback from a separate thread, so we do
  // the same in the fake camera to emulate it (and ideally trigger the same
  // races the real camera service would trigger).
  scoped_refptr<base::SequencedTaskRunner> ops_runner_;
};

}  // namespace faced::testing

#endif  // FACED_CAMERA_FAKE_CAMERA_SERVICE_H_
