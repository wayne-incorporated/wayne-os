// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_BLUETOOTH_INFO_MANAGER_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_BLUETOOTH_INFO_MANAGER_H_

#include <vector>

#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"

namespace diagnostics {

// Interface for accessing properties of Bluetooth adapters and devices.
class BluetoothInfoManager {
 public:
  explicit BluetoothInfoManager(org::bluezProxy* bluez_proxy = nullptr);
  BluetoothInfoManager(const BluetoothInfoManager&) = delete;
  BluetoothInfoManager& operator=(const BluetoothInfoManager&) = delete;
  virtual ~BluetoothInfoManager() = default;

  virtual std::vector<org::bluez::Adapter1ProxyInterface*> GetAdapters() const;
  virtual std::vector<org::bluez::Device1ProxyInterface*> GetDevices() const;
  virtual std::vector<org::bluez::AdminPolicyStatus1ProxyInterface*>
  GetAdminPolicies() const;
  virtual std::vector<org::bluez::LEAdvertisingManager1ProxyInterface*>
  GetAdvertisings() const;
  virtual std::vector<org::bluez::Battery1ProxyInterface*> GetBatteries() const;

 private:
  // Unowned pointer that should outlive this instance.
  org::bluezProxy* const bluez_proxy_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_BLUETOOTH_INFO_MANAGER_H_
