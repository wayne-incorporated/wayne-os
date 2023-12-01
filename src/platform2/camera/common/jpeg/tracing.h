/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_JPEG_TRACING_H_
#define CAMERA_COMMON_JPEG_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_JPEG(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryJpeg, ##__VA_ARGS__)

#define TRACE_JPEG_BEGIN(event, track, ...) \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryJpeg, event, track, ##__VA_ARGS__)

#define TRACE_JPEG_END(track) TRACE_EVENT_END(kCameraTraceCategoryJpeg, track)

#define TRACE_JPEG_DEBUG(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryJpegDebug, ##__VA_ARGS__)

#endif  // CAMERA_COMMON_JPEG_TRACING_H_
