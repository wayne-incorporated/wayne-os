// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_BLUETOOTH_EVENT_HUB_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_BLUETOOTH_EVENT_HUB_H_

#include <string>

#include <base/functional/callback.h>
#include <dbus/object_path.h>
#include <base/callback_list.h>

#include "diagnostics/dbus_bindings/bluetooth/dbus-proxies.h"

namespace diagnostics {

using OnBluetoothAdapterAddedCallback =
    base::RepeatingCallback<void(org::bluez::Adapter1ProxyInterface* adapter)>;
using OnBluetoothAdapterRemovedCallback =
    base::RepeatingCallback<void(const dbus::ObjectPath& adapter_path)>;
using OnBluetoothAdapterPropertyChangedCallback =
    base::RepeatingCallback<void(org::bluez::Adapter1ProxyInterface* adapter,
                                 const std::string& property_name)>;
using OnBluetoothDeviceAddedCallback =
    base::RepeatingCallback<void(org::bluez::Device1ProxyInterface* device)>;
using OnBluetoothDeviceRemovedCallback =
    base::RepeatingCallback<void(const dbus::ObjectPath& device_path)>;
using OnBluetoothDevicePropertyChangedCallback =
    base::RepeatingCallback<void(org::bluez::Device1ProxyInterface* device,
                                 const std::string& property_name)>;

// Interface for subscribing Bluetooth events.
class BluetoothEventHub {
 public:
  explicit BluetoothEventHub(org::bluezProxy* bluez_proxy = nullptr);
  BluetoothEventHub(const BluetoothEventHub&) = delete;
  BluetoothEventHub& operator=(const BluetoothEventHub&) = delete;
  ~BluetoothEventHub() = default;

  // TODO(b/270471793): To bootstrap proxy, we update proxy by the following
  // method, which should be removed after Bluez issue is fixed.
  void UpdateProxy(org::bluezProxy* bluez_proxy);

  base::CallbackListSubscription SubscribeAdapterAdded(
      OnBluetoothAdapterAddedCallback callback);
  base::CallbackListSubscription SubscribeAdapterRemoved(
      OnBluetoothAdapterRemovedCallback callback);
  base::CallbackListSubscription SubscribeAdapterPropertyChanged(
      OnBluetoothAdapterPropertyChangedCallback callback);
  base::CallbackListSubscription SubscribeDeviceAdded(
      OnBluetoothDeviceAddedCallback callback);
  base::CallbackListSubscription SubscribeDeviceRemoved(
      OnBluetoothDeviceRemovedCallback callback);
  base::CallbackListSubscription SubscribeDevicePropertyChanged(
      OnBluetoothDevicePropertyChangedCallback callback);

 protected:
  // Interfaces for subclass to send events.
  void OnAdapterAdded(org::bluez::Adapter1ProxyInterface* adapter);
  void OnAdapterRemoved(const dbus::ObjectPath& adapter_path);
  void OnAdapterPropertyChanged(org::bluez::Adapter1ProxyInterface* adapter,
                                const std::string& property_name);
  void OnDeviceAdded(org::bluez::Device1ProxyInterface* device);
  void OnDeviceRemoved(const dbus::ObjectPath& device_path);
  void OnDevicePropertyChanged(org::bluez::Device1ProxyInterface* device,
                               const std::string& property_name);

 private:
  // Observer callback list.
  base::RepeatingCallbackList<void(org::bluez::Adapter1ProxyInterface* adapter)>
      adapter_added_observers_;
  base::RepeatingCallbackList<void(const dbus::ObjectPath& adapter_path)>
      adapter_removed_observers_;
  base::RepeatingCallbackList<void(org::bluez::Adapter1ProxyInterface* adapter,
                                   const std::string& property_name)>
      adapter_property_changed_observers_;
  base::RepeatingCallbackList<void(org::bluez::Device1ProxyInterface* device)>
      device_added_observers_;
  base::RepeatingCallbackList<void(const dbus::ObjectPath& device_path)>
      device_removed_observers_;
  base::RepeatingCallbackList<void(org::bluez::Device1ProxyInterface* device,
                                   const std::string& property_name)>
      device_property_changed_observers_;

  // Must be the last class member.
  base::WeakPtrFactory<BluetoothEventHub> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_BLUETOOTH_EVENT_HUB_H_
