// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_FACTORY_H_
#define POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_FACTORY_H_

#include <memory>
#include <vector>

#include "power_manager/powerd/system/thermal/thermal_device.h"

namespace power_manager::system {

class ThermalDeviceFactory {
 public:
  ThermalDeviceFactory(const ThermalDeviceFactory&) = delete;
  ThermalDeviceFactory& operator=(const ThermalDeviceFactory&) = delete;

  // Look at default sysfs thermal device path to create ThermalDevice objects.
  static std::vector<std::unique_ptr<ThermalDeviceInterface>>
  CreateThermalDevices(const char device_list_path_for_testing[] = nullptr);

 private:
  // Private constructor to make this class static method only.
  ThermalDeviceFactory() = default;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_FACTORY_H_
