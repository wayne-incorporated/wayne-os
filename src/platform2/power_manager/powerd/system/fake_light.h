// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_FAKE_LIGHT_H_
#define POWER_MANAGER_POWERD_SYSTEM_FAKE_LIGHT_H_

#include "power_manager/powerd/system/fake_sensor_device.h"

#include <optional>
#include <string>

namespace power_manager::system {

class FakeLight : public FakeSensorDevice {
 public:
  FakeLight(bool is_color_sensor,
            std::optional<std::string> name,
            std::optional<std::string> location);

  // Implementation of FakeSensorDevice.
  cros::mojom::DeviceType GetDeviceType() const override;

  // Implementation of cros::mojom::SensorDevice.
  void GetAllChannelIds(GetAllChannelIdsCallback callback) override;

 private:
  bool is_color_sensor_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_FAKE_LIGHT_H_
