// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "diagnostics/cros_healthd/system/bluetooth_info_manager.h"

namespace diagnostics {

BluetoothInfoManager::BluetoothInfoManager(org::bluezProxy* bluez_proxy)
    : bluez_proxy_(bluez_proxy) {}

std::vector<org::bluez::Adapter1ProxyInterface*>
BluetoothInfoManager::GetAdapters() const {
  return bluez_proxy_->GetAdapter1Instances();
}
std::vector<org::bluez::Device1ProxyInterface*>
BluetoothInfoManager::GetDevices() const {
  return bluez_proxy_->GetDevice1Instances();
}
std::vector<org::bluez::AdminPolicyStatus1ProxyInterface*>
BluetoothInfoManager::GetAdminPolicies() const {
  return bluez_proxy_->GetAdminPolicyStatus1Instances();
}
std::vector<org::bluez::LEAdvertisingManager1ProxyInterface*>
BluetoothInfoManager::GetAdvertisings() const {
  return bluez_proxy_->GetLEAdvertisingManager1Instances();
}
std::vector<org::bluez::Battery1ProxyInterface*>
BluetoothInfoManager::GetBatteries() const {
  return bluez_proxy_->GetBattery1Instances();
}

}  // namespace diagnostics
