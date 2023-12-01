// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_MOCK_BLUEZ_BATTERY_PROVIDER_H_
#define POWER_MANAGER_POWERD_SYSTEM_MOCK_BLUEZ_BATTERY_PROVIDER_H_

#include <string>

#include <gmock/gmock.h>

#include "power_manager/powerd/system/bluez_battery_provider.h"

namespace power_manager::system {

class MockBluezBatteryProvider : public BluezBatteryProvider {
 public:
  MockBluezBatteryProvider() = default;
  ~MockBluezBatteryProvider() override = default;

  MOCK_METHOD(void, UpdateDeviceBattery, (const std::string&, int), (override));
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_MOCK_BLUEZ_BATTERY_PROVIDER_H_
