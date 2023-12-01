// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_BLUETOOTH_BLUEZ_PROXY_H_
#define SHILL_DBUS_BLUETOOTH_BLUEZ_PROXY_H_

#include <memory>
#include <string>

#include <dbus/bus.h>

#include "bluetooth/dbus-proxies.h"
#include "shill/bluetooth/bluetooth_bluez_proxy_interface.h"
#include "shill/event_dispatcher.h"

namespace shill {
class BluetoothBlueZProxy : public BluetoothBlueZProxyInterface {
 public:
  explicit BluetoothBlueZProxy(const scoped_refptr<dbus::Bus>& bus,
                               EventDispatcher* dispatcher);
  BluetoothBlueZProxy(const BluetoothBlueZProxy&) = delete;
  BluetoothBlueZProxy& operator=(const BluetoothBlueZProxy&) = delete;

  ~BluetoothBlueZProxy() override = default;

  bool GetAdapterPowered(bool* powered) const override;

 private:
  // Callback invoked when the value of property |property_name| is changed.
  void OnPropertyChanged(
      org::bluez::Adapter1ProxyInterface* /* proxy_interface */,
      const std::string& property_name);

  // When the BlueZ service becomes available on D-Bus, complete the setup of
  // the D-Bus proxy.
  void CompleteInitialization();

  // Callback called by the D-Bus proxy to signal that BlueZ has registered its
  // interface.
  // It's either called immediately if BlueZ is already up and running, or it's
  // called once later if BlueZ starts after shill.
  // |available| should be true in all cases.
  void OnServiceAvailable(bool /* available */);

  // Flipped to true once BlueZ has come up and the D-Bus proxy is ready to be
  // used.
  bool init_complete_;

  // Dispatcher used to post (delayed) tasks.
  EventDispatcher* dispatcher_;

  // Proxy used to communicate with BlueZ over D-Bus.
  std::unique_ptr<org::bluez::Adapter1Proxy> bluez_proxy_;

  base::WeakPtrFactory<BluetoothBlueZProxy> weak_factory_{this};
};
}  // namespace shill

#endif  //  SHILL_DBUS_BLUETOOTH_BLUEZ_PROXY_H_
