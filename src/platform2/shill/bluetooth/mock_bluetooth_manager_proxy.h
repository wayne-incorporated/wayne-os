// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_BLUETOOTH_MOCK_BLUETOOTH_MANAGER_PROXY_H_
#define SHILL_BLUETOOTH_MOCK_BLUETOOTH_MANAGER_PROXY_H_

#include <cstdint>
#include <vector>

#include <gmock/gmock.h>

#include "shill/bluetooth/bluetooth_manager_proxy_interface.h"

namespace shill {

class MockBluetoothManagerProxy : public BluetoothManagerProxyInterface {
 public:
  MockBluetoothManagerProxy();
  MockBluetoothManagerProxy(const MockBluetoothManagerProxy&) = delete;
  MockBluetoothManagerProxy& operator=(const MockBluetoothManagerProxy&) =
      delete;

  ~MockBluetoothManagerProxy() override;

  MOCK_METHOD(bool,
              GetAvailableAdapters,
              (bool,
               bool*,
               std::vector<BluetoothManagerInterface::BTAdapterWithEnabled>*),
              (const));
  MOCK_METHOD(bool, GetDefaultAdapter, (int32_t*), (const));
};

}  // namespace shill

#endif  // SHILL_BLUETOOTH_MOCK_BLUETOOTH_MANAGER_PROXY_H_
