// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/fake_camera_service.h"

#include <vector>

#include <base/logging.h>
#include <base/task/thread_pool.h>
#include <base/time/time.h>

namespace faced::testing {

namespace {

// Time between frames being sent.
//
// We schedule the frames to be sent at 30 FPS (i.e., 33ms), though we expect
// tests to be using a mock clock in practice.
constexpr base::TimeDelta kFrameInterval = base::Milliseconds(33);

}  // namespace

FakeCameraService::FakeCameraService()
    : ops_runner_(
          base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})) {}

FakeCameraService::~FakeCameraService() {
  base::AutoLock lock(mutex_);
  CHECK_NE(state_, State::kCapturing)
      << "Attempted to destroy FakeCameraService while a capture was in "
         "progress.";
}

void FakeCameraService::AddCameraInfo(cros_cam_info_t cam_info,
                                      bool is_removed) {
  base::AutoLock lock(mutex_);
  camera_infos_.push_back(cam_info);
  camera_is_removed_.push_back(is_removed);
}

void FakeCameraService::AddResult(cros_cam_capture_result_t result) {
  base::AutoLock lock(mutex_);
  results_.push_back(result);
}

int FakeCameraService::Init() {
  base::AutoLock lock(mutex_);

  CHECK_EQ(state_, State::kCreated)
      << "Attempted to call Init() in incorrect state.";
  state_ = State::kIdle;

  return 0;
}

int FakeCameraService::Exit() {
  base::AutoLock lock(mutex_);

  CHECK_EQ(state_, State::kIdle)
      << "Attempted to call Exit() in incorrect state.";
  state_ = State::kExit;

  return 0;
}

int FakeCameraService::GetCameraInfo(cros_cam_get_cam_info_cb_t callback,
                                     void* context) {
  // Make a copy of our camera information data structures, so we can issue
  // callbacks below without holding a lock.
  std::vector<cros_cam_info_t> camera_infos;
  std::vector<bool> camera_is_removed;
  {
    base::AutoLock lock(mutex_);
    camera_infos = camera_infos_;
    camera_is_removed = camera_is_removed_;
  }

  // Call the user's callback once for each camera info.
  for (int i = 0; i < camera_infos.size(); i++) {
    if ((*callback)(context, &camera_infos[i], camera_is_removed[i]) != 0) {
      return 1;
    }
  }

  return 0;
}

int FakeCameraService::StartCapture(const cros_cam_capture_request_t* request,
                                    cros_cam_capture_cb_t callback,
                                    void* context) {
  base::AutoLock lock(mutex_);

  // Update current state.
  CHECK_EQ(state_, State::kIdle)
      << "Called StartCapture() when the camera service was not in an idle "
         "state.";
  state_ = State::kCapturing;
  camera_id_ = request->id;

  // Schedule the first frame.
  ops_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&FakeCameraService::DispatchNextFrame,
                     base::Unretained(this), request, callback, context),
      kFrameInterval);
  return 0;
}

int FakeCameraService::StopCapture(int id) {
  base::AutoLock lock(mutex_);

  CHECK_EQ(state_, State::kCapturing)
      << "Attempted to call StopCapture when no capture was in progress.";
  CHECK_EQ(id, camera_id_)
      << "Called StopCapture() with the incorrect camera ID.";

  // The camera service API guarantees that when StopCapture() returns,
  // no new callsback will be issued.
  state_ = State::kIdle;

  return 0;
}

void FakeCameraService::DispatchNextFrame(
    const cros_cam_capture_request_t* request,
    cros_cam_capture_cb_t callback,
    void* context) {
  CHECK(ops_runner_->RunsTasksInCurrentSequence());

  base::AutoLock lock(mutex_);

  // If StopCapture() has been called, don't dispatch any more frames.
  if (state_ != State::kCapturing) {
    return;
  }

  // If we have run out of frames, just stall the stream.
  if (results_.empty()) {
    return;
  }

  // Fetch the next frame, and send it to the user's callback.
  //
  // If a non-zero value is returned, we stop the current capture.
  cros_cam_capture_result_t result = results_.front();
  results_.pop_front();
  bool should_continue = ((*callback)(context, &result) == 0);
  if (!should_continue) {
    state_ = State::kIdle;
    return;
  }

  // Schedule the next frame.
  ops_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&FakeCameraService::DispatchNextFrame,
                     base::Unretained(this), request, callback, context),
      kFrameInterval);
}

}  // namespace faced::testing
