// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_FRAME_UTILS_H_
#define FACED_CAMERA_FRAME_UTILS_H_

#include <memory>
#include <string>

#include "cros-camera/camera_service_connector.h"
#include "faced/camera/frame.h"

namespace faced {

// Generates a Frame object from a CrOS camera frame.
std::unique_ptr<Frame> FrameFromCrosFrame(const cros_cam_frame_t& frame);

//
// Internal implementation details (exposed for testing) below.
//

// Returns a tightly packed YUV payload with any padding removed
std::string GetTightlyPackedPayload(int height,
                                    int width,
                                    const cros_cam_plane_t_& plane_y,
                                    const cros_cam_plane_t_& plane_uv);

}  // namespace faced

#endif  // FACED_CAMERA_FRAME_UTILS_H_
