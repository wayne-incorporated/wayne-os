/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_COMMON_TRACING_H_
#define CAMERA_COMMON_COMMON_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_COMMON(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryCommon, ##__VA_ARGS__)

#define TRACE_COMMON_EVENT(event, ...) \
  TRACE_EVENT(kCameraTraceCategoryCommon, event, ##__VA_ARGS__)

#define TRACE_COMMON_BEGIN(event, track, ...) \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryCommon, event, track, ##__VA_ARGS__)

#define TRACE_COMMON_END(track, ...) \
  TRACE_EVENT_END(kCameraTraceCategoryCommon, track, ##__VA_ARGS__)

#endif  // CAMERA_COMMON_COMMON_TRACING_H_
