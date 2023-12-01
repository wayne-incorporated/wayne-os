// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_BLUETOOTH_EVENT_HUB_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_BLUETOOTH_EVENT_HUB_H_

#include <string>

#include <dbus/object_path.h>

#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"

namespace diagnostics {

class FakeBluetoothEventHub final : public BluetoothEventHub {
 public:
  FakeBluetoothEventHub() = default;
  FakeBluetoothEventHub(const FakeBluetoothEventHub&) = delete;
  FakeBluetoothEventHub& operator=(const FakeBluetoothEventHub&) = delete;

  // Send fake events.
  void SendAdapterAdded(org::bluez::Adapter1ProxyInterface* adapter = nullptr);
  void SendAdapterRemoved(
      const dbus::ObjectPath& adapter_path = dbus::ObjectPath(""));
  void SendAdapterPropertyChanged(
      org::bluez::Adapter1ProxyInterface* adapter = nullptr,
      const std::string& property_name = "");
  void SendDeviceAdded(org::bluez::Device1ProxyInterface* device = nullptr);
  void SendDeviceRemoved(
      const dbus::ObjectPath& device_path = dbus::ObjectPath(""));
  void SendDevicePropertyChanged(
      org::bluez::Device1ProxyInterface* device = nullptr,
      const std::string& property_name = "");
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_BLUETOOTH_EVENT_HUB_H_
