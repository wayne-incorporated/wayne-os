/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_AUTO_FRAMING_TRACING_H_
#define CAMERA_FEATURES_AUTO_FRAMING_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_AUTO_FRAMING(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryAutoFraming, ##__VA_ARGS__)

#define TRACE_AUTO_FRAMING_BEGIN(...) \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryAutoFraming, ##__VA_ARGS__)

#define TRACE_AUTO_FRAMING_END() \
  TRACE_EVENT_END(kCameraTraceCategoryAutoFraming)

#endif  // CAMERA_FEATURES_AUTO_FRAMING_TRACING_H_
