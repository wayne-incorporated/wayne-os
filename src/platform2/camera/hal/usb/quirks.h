/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_QUIRKS_H_
#define CAMERA_HAL_USB_QUIRKS_H_

#include <cstdint>
#include <string>

#include "hal/usb/common_types.h"

namespace cros {

// The bitmask for each quirk.
enum : uint32_t {
  kQuirkPreferMjpeg = 1 << 0,
  kQuirkRestartOnTimeout = 1 << 1,
  kQuirkReportLeastFpsRanges = 1 << 2,
  kQuirkDisableFrameRateSetting = 1 << 3,
  kQuirkV1Device = 1 << 4,
  kQuirkUserSpaceTimestamp = 1 << 5,
  kQuirkAndroidExternal = 1 << 6,
  kQuirkPreferLargePreviewResolution = 1 << 7,
  kQuirkInfrared = 1 << 8,
  kQuirkAndroidLegacy = 1 << 9,
};

uint32_t GetQuirks(const std::string& vid, const std::string& pid);

}  // namespace cros

#endif  // CAMERA_HAL_USB_QUIRKS_H_
