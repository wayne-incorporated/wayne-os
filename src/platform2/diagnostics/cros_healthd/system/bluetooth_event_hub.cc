// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"

#include <string>

namespace diagnostics {

BluetoothEventHub::BluetoothEventHub(org::bluezProxy* bluez_proxy) {
  UpdateProxy(bluez_proxy);
}

void BluetoothEventHub::UpdateProxy(org::bluezProxy* bluez_proxy) {
  if (!bluez_proxy)
    return;
  bluez_proxy->SetAdapter1AddedCallback(base::BindRepeating(
      &BluetoothEventHub::OnAdapterAdded, weak_ptr_factory_.GetWeakPtr()));
  bluez_proxy->SetAdapter1RemovedCallback(base::BindRepeating(
      &BluetoothEventHub::OnAdapterRemoved, weak_ptr_factory_.GetWeakPtr()));
  bluez_proxy->SetDevice1AddedCallback(base::BindRepeating(
      &BluetoothEventHub::OnDeviceAdded, weak_ptr_factory_.GetWeakPtr()));
  bluez_proxy->SetDevice1RemovedCallback(base::BindRepeating(
      &BluetoothEventHub::OnDeviceRemoved, weak_ptr_factory_.GetWeakPtr()));
}

base::CallbackListSubscription BluetoothEventHub::SubscribeAdapterAdded(
    OnBluetoothAdapterAddedCallback callback) {
  return adapter_added_observers_.Add(callback);
}

base::CallbackListSubscription BluetoothEventHub::SubscribeAdapterRemoved(
    OnBluetoothAdapterRemovedCallback callback) {
  return adapter_removed_observers_.Add(callback);
}

base::CallbackListSubscription
BluetoothEventHub::SubscribeAdapterPropertyChanged(
    OnBluetoothAdapterPropertyChangedCallback callback) {
  return adapter_property_changed_observers_.Add(callback);
}

base::CallbackListSubscription BluetoothEventHub::SubscribeDeviceAdded(
    OnBluetoothDeviceAddedCallback callback) {
  return device_added_observers_.Add(callback);
}

base::CallbackListSubscription BluetoothEventHub::SubscribeDeviceRemoved(
    OnBluetoothDeviceRemovedCallback callback) {
  return device_removed_observers_.Add(callback);
}

base::CallbackListSubscription
BluetoothEventHub::SubscribeDevicePropertyChanged(
    OnBluetoothDevicePropertyChangedCallback callback) {
  return device_property_changed_observers_.Add(callback);
}

void BluetoothEventHub::OnAdapterAdded(
    org::bluez::Adapter1ProxyInterface* adapter) {
  if (adapter) {
    adapter->SetPropertyChangedCallback(
        base::BindRepeating(&BluetoothEventHub::OnAdapterPropertyChanged,
                            weak_ptr_factory_.GetWeakPtr()));
  }
  adapter_added_observers_.Notify(adapter);
}

void BluetoothEventHub::OnAdapterRemoved(const dbus::ObjectPath& adapter_path) {
  adapter_removed_observers_.Notify(adapter_path);
}

void BluetoothEventHub::OnAdapterPropertyChanged(
    org::bluez::Adapter1ProxyInterface* adapter,
    const std::string& property_name) {
  adapter_property_changed_observers_.Notify(adapter, property_name);
}

void BluetoothEventHub::OnDeviceAdded(
    org::bluez::Device1ProxyInterface* device) {
  if (device) {
    device->SetPropertyChangedCallback(
        base::BindRepeating(&BluetoothEventHub::OnDevicePropertyChanged,
                            weak_ptr_factory_.GetWeakPtr()));
  }
  device_added_observers_.Notify(device);
}

void BluetoothEventHub::OnDeviceRemoved(const dbus::ObjectPath& device_path) {
  device_removed_observers_.Notify(device_path);
}

void BluetoothEventHub::OnDevicePropertyChanged(
    org::bluez::Device1ProxyInterface* device,
    const std::string& property_name) {
  device_property_changed_observers_.Notify(device, property_name);
}

}  // namespace diagnostics
