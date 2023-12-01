// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_BLUETOOTH_ADAPTER_PROXY_H_
#define SHILL_DBUS_BLUETOOTH_ADAPTER_PROXY_H_

#include <cstdint>
#include <memory>

#include <dbus/bus.h>

#include "bluetooth/dbus-proxies.h"
#include "shill/bluetooth/bluetooth_adapter_proxy_interface.h"
#include "shill/bluetooth/bluetooth_manager_interface.h"

namespace shill {

class BluetoothAdapterProxy : public BluetoothAdapterProxyInterface {
 public:
  explicit BluetoothAdapterProxy(const scoped_refptr<dbus::Bus>& bus,
                                 int32_t hci);

  ~BluetoothAdapterProxy() override = default;

  bool GetProfileConnectionState(
      BluetoothManagerInterface::BTProfile profile,
      BluetoothManagerInterface::BTProfileConnectionState* state)
      const override;

  bool IsDiscovering(bool* discovering) const override;

 private:
  std::unique_ptr<org::chromium::bluetooth::BluetoothProxy> proxy_;
};

}  // namespace shill

#endif  // SHILL_DBUS_BLUETOOTH_ADAPTER_PROXY_H_
