// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_BLUETOOTH_MANAGER_PROXY_H_
#define SHILL_DBUS_BLUETOOTH_MANAGER_PROXY_H_

#include <cstdint>
#include <memory>
#include <vector>

#include <dbus/dbus.h>

#include "bluetooth/dbus-proxies.h"
#include "shill/bluetooth/bluetooth_manager_interface.h"
#include "shill/bluetooth/bluetooth_manager_proxy_interface.h"
#include "shill/event_dispatcher.h"

namespace shill {

class BluetoothManagerProxy : public BluetoothManagerProxyInterface {
 public:
  explicit BluetoothManagerProxy(
      const scoped_refptr<dbus::Bus>& bus,
      EventDispatcher* dispatcher_,
      const base::RepeatingClosure& service_appeared_callback);
  BluetoothManagerProxy(const BluetoothManagerProxy&) = delete;
  BluetoothManagerProxy& operator=(const BluetoothManagerProxy&) = delete;

  ~BluetoothManagerProxy() override = default;

  bool GetAvailableAdapters(
      bool force_query,
      bool* is_floss,
      std::vector<BluetoothManagerInterface::BTAdapterWithEnabled>* adapters)
      const override;

  bool GetDefaultAdapter(int32_t* hci) const override;

 private:
  // Query BT manager to know if BT uses Floss or not. Returns true if the query
  // was successful, false otherwise. If the query was successful, |enabled| is
  // set to true if the device is using Floss, false otherwise.
  bool GetFlossEnabled(bool* enabled) const;

  // Callback called by the D-Bus proxy to signal that btmanagerd has registered
  // its interface.
  // It's either called immediately if btmanagerd is already up and running, or
  // it's called once later if btmanagerd starts after shill.
  // |available| should be true in all cases.
  void OnServiceAvailable(bool /* available */) const;

  // There can be a delay between btmanagerd registering its interface on D-Bus
  // and btmanagerd being ready to service D-Bus requests. Call this function to
  // signal to |BluetoothManager| that btmanagerd is ready to service D-Bus
  // queries.
  void OnServiceReady() const;

  // Proxy used to communicate with btmanagerd.
  std::unique_ptr<org::chromium::bluetooth::ManagerProxy> manager_proxy_;

  // Dispatcher used to post (delayed) tasks.
  EventDispatcher* dispatcher_;

  // Run this callback when btmanagerd appears on D-Bus.
  base::RepeatingClosure service_appeared_callback_;

  base::WeakPtrFactory<BluetoothManagerProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_BLUETOOTH_MANAGER_PROXY_H_
