/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_EGL_UTILS_H_
#define CAMERA_GPU_EGL_UTILS_H_

#include <EGL/egl.h>

namespace cros {

// Utility function to get printable strings for the EGL error.
const char* EglGetErrorString(EGLint error);

// Dumps various EGL info.
void EglDumpInfo();

}  // namespace cros

#endif  // CAMERA_GPU_EGL_UTILS_H_
