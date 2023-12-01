/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_TRACING_H_
#define CAMERA_HAL_USB_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_USB_HAL(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryUsbHal, ##__VA_ARGS__)

#endif  // CAMERA_HAL_USB_TRACING_H_
