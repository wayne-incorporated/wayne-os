// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_MOCK_BLUETOOTH_INFO_MANAGER_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_MOCK_BLUETOOTH_INFO_MANAGER_H_

#include <vector>

#include "diagnostics/cros_healthd/system/bluetooth_info_manager.h"

namespace diagnostics {

class MockBluetoothInfoManager final : public BluetoothInfoManager {
 public:
  MockBluetoothInfoManager() = default;
  MockBluetoothInfoManager(const MockBluetoothInfoManager&) = delete;
  MockBluetoothInfoManager& operator=(const MockBluetoothInfoManager&) = delete;
  ~MockBluetoothInfoManager() = default;

  MOCK_METHOD(std::vector<org::bluez::Adapter1ProxyInterface*>,
              GetAdapters,
              (),
              (const, override));
  MOCK_METHOD(std::vector<org::bluez::Device1ProxyInterface*>,
              GetDevices,
              (),
              (const, override));
  MOCK_METHOD(std::vector<org::bluez::AdminPolicyStatus1ProxyInterface*>,
              GetAdminPolicies,
              (),
              (const, override));
  MOCK_METHOD(std::vector<org::bluez::LEAdvertisingManager1ProxyInterface*>,
              GetAdvertisings,
              (),
              (const, override));
  MOCK_METHOD(std::vector<org::bluez::Battery1ProxyInterface*>,
              GetBatteries,
              (),
              (const, override));
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_MOCK_BLUETOOTH_INFO_MANAGER_H_
