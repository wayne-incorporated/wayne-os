/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_TRANSFORM_H_
#define CAMERA_GPU_GLES_TRANSFORM_H_

#include <vector>

namespace cros {

// Returns a 4x4 transformation matrix that converts to the texture coordinate
// in [0, 1]^2 from a given normalized device coordinate in [-1, 1]^2.
std::vector<float> TextureSpaceFromNdc();

}  // namespace cros

#endif  // CAMERA_GPU_GLES_TRANSFORM_H_
