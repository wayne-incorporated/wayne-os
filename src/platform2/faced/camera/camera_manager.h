// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_CAMERA_MANAGER_H_
#define FACED_CAMERA_CAMERA_MANAGER_H_

#include <memory>

#include <absl/status/statusor.h>

#include "faced/camera/frame.h"
#include "faced/util/stream.h"

namespace faced {

// A StreamReader of camera frames.
//
// By convention, the stream should consist of an infinite stream of camera
// frames, terminated by a single absl::Status if an error is encountered.
// Provides access to the system camera as a series of Frames.
using CameraStreamValue = absl::StatusOr<std::unique_ptr<Frame>>;
using CameraStreamReader = StreamReader<CameraStreamValue>;

class CameraManager {
 public:
  virtual ~CameraManager() = default;

  // Start the camera.
  //
  // The returned stream will contain frames read from the camera.
  //
  // Returns an error if the camera is already open, or if early initialisation
  // fails. Errors encountered after initial initialisation of the camera will
  // be reported via the CameraStreamReader as a final value on the stream.
  virtual absl::StatusOr<std::unique_ptr<CameraStreamReader>> Open() = 0;

  // Close any existing stream.
  //
  // The camera is stopped once the given closure is called.
  //
  // Close() may be safely called even if no streams are open. If a stream is
  // open, a final status with code `CancelledError` will be written to the
  // stream, and the stream closed.
  virtual void Close(base::OnceClosure close_complete) = 0;
};

}  // namespace faced

#endif  // FACED_CAMERA_CAMERA_MANAGER_H_
