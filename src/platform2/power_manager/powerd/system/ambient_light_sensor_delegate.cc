// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_delegate.h"

#include <optional>
#include <utility>

#include <base/logging.h>

namespace power_manager::system {

// static
std::optional<int> AmbientLightSensorDelegate::CalculateColorTemperature(
    const std::map<ChannelType, int>& readings) {
  const auto it_x = readings.find(ChannelType::X),
             it_y = readings.find(ChannelType::Y),
             it_z = readings.find(ChannelType::Z);
  if (it_x == readings.end() || it_y == readings.end() ||
      it_z == readings.end()) {
    return std::nullopt;
  }

  double scale_factor = it_x->second + it_y->second + it_z->second;
  if (scale_factor <= 0.0)
    return std::nullopt;

  double scaled_x = it_x->second / scale_factor;
  double scaled_y = it_y->second / scale_factor;
  // Avoid weird behavior around the function's pole.
  if (scaled_y < 0.186)
    return std::nullopt;

  double n = (scaled_x - 0.3320) / (0.1858 - scaled_y);

  int color_temperature =
      static_cast<int>(449 * n * n * n + 3525 * n * n + 6823.3 * n + 5520.33);
  VLOG(1) << "Color temperature: " << color_temperature;

  return color_temperature;
}

void AmbientLightSensorDelegate::SetLuxCallback(
    base::RepeatingCallback<void(std::optional<int>, std::optional<int>)>
        set_lux_callback) {
  set_lux_callback_ = std::move(set_lux_callback);
}

}  // namespace power_manager::system
