/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_UTILS_H_
#define CAMERA_GPU_GLES_UTILS_H_

#include <string>

#include <GLES3/gl3.h>

namespace cros {

// Utility function to get printable strings for the GL error.
std::string GlGetErrorString(GLint error);

// Dumps various GL info.
void GlDumpInfo();

}  // namespace cros

#endif  // CAMERA_GPU_GLES_UTILS_H_
