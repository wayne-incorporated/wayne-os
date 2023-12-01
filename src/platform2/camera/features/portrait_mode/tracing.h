/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_PORTRAIT_MODE_TRACING_H_
#define CAMERA_FEATURES_PORTRAIT_MODE_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_PORTRAIT_MODE(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryPortraitMode, ##__VA_ARGS__)

#endif  // CAMERA_FEATURES_PORTRAIT_MODE_TRACING_H_
