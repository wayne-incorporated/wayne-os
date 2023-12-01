// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_BLUETOOTH_BLUETOOTH_MANAGER_PROXY_INTERFACE_H_
#define SHILL_BLUETOOTH_BLUETOOTH_MANAGER_PROXY_INTERFACE_H_

#include <cstdint>
#include <vector>

#include "shill/bluetooth/bluetooth_manager_interface.h"

namespace shill {

class BluetoothManagerProxyInterface {
 public:
  virtual ~BluetoothManagerProxyInterface() = default;

  // If |force_query| is true, shill will request the list of available adapters
  // from btmanagerd even if Floss is disabled. Otherwise, if Floss is disabled
  // shill will skip the discovery of available adapters to avoid a D-Bus
  // roundtrip to btmanagerd since btmanagerd does not know if devices are
  // enabled or not when BlueZ is in use.
  virtual bool GetAvailableAdapters(
      bool force_query,
      bool* is_floss,
      std::vector<BluetoothManagerInterface::BTAdapterWithEnabled>* adapters)
      const = 0;

  virtual bool GetDefaultAdapter(int32_t* hci) const = 0;
};

}  // namespace shill

#endif  // SHILL_BLUETOOTH_BLUETOOTH_MANAGER_PROXY_INTERFACE_H_
