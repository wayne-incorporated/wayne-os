// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"

#include <base/check.h>
#include <base/logging.h>
#include <dbus/bluetooth/dbus-constants.h>

namespace diagnostics {
namespace wilco {

BluetoothClient::AdapterProperties::AdapterProperties(
    dbus::ObjectProxy* object_proxy,
    const dbus::PropertySet::PropertyChangedCallback& callback)
    : dbus::PropertySet(object_proxy,
                        bluetooth_adapter::kBluetoothAdapterInterface,
                        callback) {
  RegisterProperty(bluetooth_adapter::kNameProperty, &name);
  RegisterProperty(bluetooth_adapter::kAddressProperty, &address);
  RegisterProperty(bluetooth_adapter::kPoweredProperty, &powered);
}

BluetoothClient::AdapterProperties::~AdapterProperties() = default;

BluetoothClient::DeviceProperties::DeviceProperties(
    dbus::ObjectProxy* object_proxy,
    const dbus::PropertySet::PropertyChangedCallback& callback)
    : dbus::PropertySet(
          object_proxy, bluetooth_device::kBluetoothDeviceInterface, callback) {
  RegisterProperty(bluetooth_device::kNameProperty, &name);
  RegisterProperty(bluetooth_device::kAddressProperty, &address);
  RegisterProperty(bluetooth_device::kConnectedProperty, &connected);
  RegisterProperty(bluetooth_device::kAdapterProperty, &adapter);
}

BluetoothClient::DeviceProperties::~DeviceProperties() = default;

BluetoothClient::BluetoothClient() = default;

BluetoothClient::~BluetoothClient() = default;

void BluetoothClient::AddObserver(Observer* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void BluetoothClient::RemoveObserver(Observer* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

}  // namespace wilco
}  // namespace diagnostics
