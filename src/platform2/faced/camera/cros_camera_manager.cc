// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/cros_camera_manager.h"

#include <utility>

#include <absl/status/status.h>

#include "base/functional/callback_forward.h"
#include "base/memory/scoped_refptr.h"
#include "faced/camera/camera_client.h"
#include "faced/camera/camera_manager.h"
#include "faced/util/queueing_stream.h"
#include "faced/util/task.h"

namespace faced {
namespace {

// Queue at most two frames.
//
// We need at least two frames for QueueingStream's "expedite" feature to work,
// where it detects a backlog of work and requests new frames to be expedited.
// However, a large queue introduces lag: that is, the visible UI represents the
// state of the camera _N_ frames ago.
constexpr int kMaxQueuedFrames = 2;

// A `FrameProcessor` that enqueues frames to a QueueingStream.
class StreamingFrameProcessor : public faced::FrameProcessor {
 public:
  explicit StreamingFrameProcessor(
      QueueingStream<absl::StatusOr<std::unique_ptr<Frame>>>& stream)
      : stream_(stream) {}

  // Process a frame from the camera.
  void ProcessFrame(std::unique_ptr<Frame> frame,
                    ProcessFrameDoneCallback done) override {
    // Attempt to write the frame to the stream. If the stream has closed, stop
    // the camera.
    std::optional<absl::Status> result;
    if (!stream_.Write(std::move(frame))) {
      result = absl::CancelledError();
    }
    PostToCurrentSequence(base::BindOnce(std::move(done), result));
  }

 private:
  ~StreamingFrameProcessor() override = default;

  QueueingStream<absl::StatusOr<std::unique_ptr<Frame>>> stream_;
};

}  // namespace

CrosCameraManager::CrosCameraManager(
    CameraClient& client, const CameraClient::CaptureFramesConfig& config)
    : camera_(client), config_(config) {}

CrosCameraManager::~CrosCameraManager() {
  CHECK(!stream_.has_value())
      << "CrosCameraManager destroyed while still active.";
}

absl::StatusOr<std::unique_ptr<CameraStreamReader>> CrosCameraManager::Open() {
  // If a reader already exists, abort with an error.
  if (stream_.has_value()) {
    return absl::AlreadyExistsError("Camera already open.");
  }

  // Create a queue for the camera frames.
  stream_.emplace(/*max_queue_size=*/kMaxQueuedFrames);

  // Start streaming frames.
  auto processor = base::MakeRefCounted<StreamingFrameProcessor>(*stream_);
  camera_.CaptureFrames(config_, std::move(processor),
                        base::BindOnce(&CrosCameraManager::OnCameraClosed,
                                       base::Unretained(this)));

  return stream_->GetReader();
}

void CrosCameraManager::Close(base::OnceClosure close_complete) {
  CHECK(close_complete_.is_null()) << "Close already in progress.";

  // If no session is open, simply call the callback.
  if (!stream_.has_value()) {
    PostToCurrentSequence(std::move(close_complete));
    return;
  }

  // Close the stream.
  //
  // Next time a frame arrives, the camera client should detect that the stream
  // is closed, clean up, and trigger the callback.
  //
  // TODO(b/254429209): It would be preferable if we could just stop the camera
  // directly here, and not need to perform the async wait.
  close_complete_ = std::move(close_complete);
  stream_->Write(absl::CancelledError());
  stream_->Close();
}

void CrosCameraManager::OnCameraClosed(absl::Status final_status) {
  DCHECK(stream_.has_value());

  // The camera may have closed because of an error, because the reader
  // closed the stream, or because Close() was called on us.
  //
  // In any case, we must:
  //
  // * Write out an error to the stream, if it is still open.
  // * Close the stream.
  // * Complete any pending close callback.

  // Write out the error to the stream, and close it.
  //
  // It may already be closed: that's fine. We assume that an error was
  // already written out.
  stream_->Write(final_status);
  stream_->Close();
  stream_.reset();

  // Notify any potential waiters that the close is finished.
  //
  // If this cleanup was not triggered by a Close(), there may not be
  // any one waiting. That's fine: any future `Close()` will just be
  // a no-op.
  if (!close_complete_.is_null()) {
    PostToCurrentSequence(std::move(close_complete_));
  }
}

}  // namespace faced
