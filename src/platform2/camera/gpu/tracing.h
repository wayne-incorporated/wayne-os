/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_TRACING_H_
#define CAMERA_GPU_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_GPU(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryGpu, ##__VA_ARGS__)

#define TRACE_GPU_DEBUG(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryGpuDebug, ##__VA_ARGS__)

#endif  // CAMERA_GPU_TRACING_H_
