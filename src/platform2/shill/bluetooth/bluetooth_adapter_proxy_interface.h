// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_BLUETOOTH_BLUETOOTH_ADAPTER_PROXY_INTERFACE_H_
#define SHILL_BLUETOOTH_BLUETOOTH_ADAPTER_PROXY_INTERFACE_H_

#include <cstdint>

#include "shill/bluetooth/bluetooth_manager_interface.h"

namespace shill {

// |BluetoothAdapterProxyInterface| is the interface that queries BT adapters
// when the device uses Floss and BT is enabled.
// This interface should not be used directly, |BluetoothManagerInterface|
// is the primary interface used to communicate with the BT stack.
class BluetoothAdapterProxyInterface {
 public:
  virtual ~BluetoothAdapterProxyInterface() = default;

  // See BluetoothManagerInterface::GetProfileConnectionState().
  virtual bool GetProfileConnectionState(
      BluetoothManagerInterface::BTProfile profile,
      BluetoothManagerInterface::BTProfileConnectionState* state) const = 0;

  // See BluetoothManagerInterface::IsDiscovering()
  virtual bool IsDiscovering(bool* discovering) const = 0;
};

}  // namespace shill

#endif  // SHILL_BLUETOOTH_BLUETOOTH_ADAPTER_PROXY_INTERFACE_H_
