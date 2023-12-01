// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_BLUETOOTH_BLUETOOTH_BLUEZ_PROXY_INTERFACE_H_
#define SHILL_BLUETOOTH_BLUETOOTH_BLUEZ_PROXY_INTERFACE_H_

namespace shill {

class BluetoothBlueZProxyInterface {
 public:
  virtual ~BluetoothBlueZProxyInterface() = default;

  virtual bool GetAdapterPowered(bool* powered) const = 0;
};

}  // namespace shill

#endif  // SHILL_BLUETOOTH_BLUETOOTH_BLUEZ_PROXY_INTERFACE_H_
