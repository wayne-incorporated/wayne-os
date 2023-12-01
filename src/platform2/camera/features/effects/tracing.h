/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_EFFECTS_TRACING_H_
#define CAMERA_FEATURES_EFFECTS_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_EFFECTS(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryEffects, ##__VA_ARGS__)

#define TRACE_EFFECTS_BEGIN(...) \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryEffects, ##__VA_ARGS__)

#define TRACE_EFFECTS_END() TRACE_EVENT_END(kCameraTraceCategoryEffects)

#endif  // CAMERA_FEATURES_EFFECTS_TRACING_H_
