/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_TIMEZONE_H_
#define CAMERA_INCLUDE_CROS_CAMERA_TIMEZONE_H_

#include <linux/v4l2-controls.h>

#include <string>
#include <optional>

#include "cros-camera/export.h"

namespace cros {

// Checks the system timezone and turns it into a two-character ASCII country
// code. This may fail (for example, it will always fail on Android), in which
// case it will return an empty string.
CROS_CAMERA_EXPORT std::string CountryCodeForCurrentTimezone();

// Queries timezone to know the country to decide power frequency to do
// anti-banding.
CROS_CAMERA_EXPORT std::optional<v4l2_power_line_frequency>
GetPowerLineFrequencyForLocation();

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_TIMEZONE_H_
