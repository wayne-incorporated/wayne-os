// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/fake_light.h"

#include <utility>
#include <vector>

#include "power_manager/powerd/system/ambient_light_sensor_delegate_mojo.h"

namespace power_manager::system {

FakeLight::FakeLight(bool is_color_sensor,
                     std::optional<std::string> name,
                     std::optional<std::string> location)
    : is_color_sensor_(is_color_sensor) {
  if (name.has_value())
    SetAttribute(cros::mojom::kDeviceName, name.value());

  if (location.has_value())
    SetAttribute(cros::mojom::kLocation, location.value());
}

cros::mojom::DeviceType FakeLight::GetDeviceType() const {
  return cros::mojom::DeviceType::LIGHT;
}

void FakeLight::GetAllChannelIds(GetAllChannelIdsCallback callback) {
  std::vector<std::string> channel_ids(1, cros::mojom::kLightChannel);
  if (is_color_sensor_) {
    for (const ColorChannelInfo& channel : kColorChannelConfig) {
      channel_ids.push_back(
          AmbientLightSensorDelegateMojo::GetChannelIlluminanceColorId(
              channel.rgb_name));
    }
  }
  channel_ids.push_back(cros::mojom::kTimestampChannel);
  std::move(callback).Run(std::move(channel_ids));
}

}  // namespace power_manager::system
