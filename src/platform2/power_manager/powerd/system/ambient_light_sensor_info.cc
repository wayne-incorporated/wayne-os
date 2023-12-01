// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_info.h"

#include <tuple>

namespace power_manager::system {

bool AmbientLightSensorInfo::operator<(
    const AmbientLightSensorInfo& rhs) const {
  return std::tie(iio_path.value(), device) <
         std::tie(rhs.iio_path.value(), rhs.device);
}

bool AmbientLightSensorInfo::operator==(const AmbientLightSensorInfo& o) const {
  return !(*this < o || o < *this);
}

}  // namespace power_manager::system
