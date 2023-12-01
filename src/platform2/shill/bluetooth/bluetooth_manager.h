// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_BLUETOOTH_BLUETOOTH_MANAGER_H_
#define SHILL_BLUETOOTH_BLUETOOTH_MANAGER_H_

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include <base/memory/weak_ptr.h>

#include "shill/bluetooth/bluetooth_adapter_proxy_interface.h"
#include "shill/bluetooth/bluetooth_bluez_proxy_interface.h"
#include "shill/bluetooth/bluetooth_manager_interface.h"
#include "shill/bluetooth/bluetooth_manager_proxy_interface.h"

namespace shill {
class ControlInterface;

class BluetoothManager : public BluetoothManagerInterface {
 public:
  explicit BluetoothManager(ControlInterface* control_interface);
  BluetoothManager(const BluetoothManager&) = delete;
  BluetoothManager& operator=(const BluetoothManager&) = delete;

  ~BluetoothManager() override = default;

  bool Start() override;

  void Stop() override;

  bool GetAvailableAdapters(
      bool* is_floss,
      std::vector<BluetoothManagerInterface::BTAdapterWithEnabled>* adapters)
      const override;

  bool GetDefaultAdapter(int32_t* hci) const override;

  bool GetProfileConnectionState(
      int32_t hci,
      BTProfile profile,
      BTProfileConnectionState* state) const override;

  bool IsDiscovering(int32_t hci, bool* discovering) const override;

 private:
  // Tear-down D-Bus proxies to the BT stack.
  void TearDown();

  // Callback called by |BluetoothManagerProxy| to signal that btmanagerd has
  // registered its D-Bus interface and that the proxy is ready to be used.
  // It's either called immediately if btmanagerd is already up and running, or
  // it's called once later if btmanagerd starts after shill.
  void OnBTManagerAvailable();

  // When the btmanagerd service becomes available on D-Bus, complete the setup
  // of the various D-Bus proxies (btmanagerd, BlueZ, Floss adapters).
  // Note that it will complete the initialization of all the D-Bus proxies for
  // Floss. It will auto start the initialization of the BlueZ proxy, but the
  // completion of the initialization of the BlueZ proxy is owned by
  // |BluetoothBlueZProxy|.
  void CompleteInitialization();

  // Flipped to true once the D-Bus proxies for btmanagerd are up and running.
  bool init_complete_;

  ControlInterface* control_interface_;

  std::unique_ptr<BluetoothManagerProxyInterface> bluetooth_manager_proxy_;

  // A single btmanager can handle several BT adapters. This is a map of the
  // proxies to communicate with the various BT adapters that is indexed on the
  // HCI index of those adapters.
  std::map<int32_t, std::unique_ptr<BluetoothAdapterProxyInterface>>
      adapter_proxies_;

  std::unique_ptr<BluetoothBlueZProxyInterface> bluez_proxy_;

  base::WeakPtrFactory<BluetoothManager> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_BLUETOOTH_BLUETOOTH_MANAGER_H_
