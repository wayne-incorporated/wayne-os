// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service_impl.h"

#include <algorithm>
#include <utility>

#include <base/check.h>

namespace diagnostics {
namespace wilco {

BluetoothEventServiceImpl::BluetoothEventServiceImpl(
    BluetoothClient* bluetooth_client)
    : bluetooth_client_(bluetooth_client) {
  DCHECK(bluetooth_client_);
  bluetooth_client_->AddObserver(this);
}

BluetoothEventServiceImpl::~BluetoothEventServiceImpl() {
  bluetooth_client_->RemoveObserver(this);
}

const std::vector<BluetoothEventService::AdapterData>&
BluetoothEventServiceImpl::GetLatestEvent() {
  return last_adapters_data_;
}

void BluetoothEventServiceImpl::AdapterAdded(
    const dbus::ObjectPath& adapter_path,
    const BluetoothClient::AdapterProperties& properties) {
  AdapterChanged(adapter_path, properties);
  UpdateAdaptersData();
}

void BluetoothEventServiceImpl::AdapterRemoved(
    const dbus::ObjectPath& adapter_path) {
  adapters_.erase(adapter_path);
  connected_devices_.erase(adapter_path);
  UpdateAdaptersData();
}

void BluetoothEventServiceImpl::AdapterPropertyChanged(
    const dbus::ObjectPath& adapter_path,
    const BluetoothClient::AdapterProperties& properties) {
  AdapterChanged(adapter_path, properties);
  UpdateAdaptersData();
}

void BluetoothEventServiceImpl::DeviceAdded(
    const dbus::ObjectPath& device_path,
    const BluetoothClient::DeviceProperties& properties) {
  DeviceChanged(device_path, properties);
  UpdateAdaptersData();
}

void BluetoothEventServiceImpl::DeviceRemoved(
    const dbus::ObjectPath& device_path) {
  RemoveConnectedDevice(device_path);
  UpdateAdaptersData();
}

void BluetoothEventServiceImpl::DevicePropertyChanged(
    const dbus::ObjectPath& device_path,
    const BluetoothClient::DeviceProperties& properties) {
  DeviceChanged(device_path, properties);
  UpdateAdaptersData();
}

void BluetoothEventServiceImpl::AdapterChanged(
    const dbus::ObjectPath& adapter_path,
    const BluetoothClient::AdapterProperties& properties) {
  auto adapters_iter = adapters_.find(adapter_path);
  if (adapters_iter != adapters_.end()) {
    adapters_iter->second.name = properties.name.value();
    adapters_iter->second.address = properties.address.value();
    adapters_iter->second.powered = properties.powered.value();
    return;
  }

  std::set<dbus::ObjectPath> devices;

  AdapterData adapter;
  adapter.name = properties.name.value();
  adapter.address = properties.address.value();
  adapter.powered = properties.powered.value();
  adapter.connected_devices_count =
      static_cast<uint32_t>(connected_devices_[adapter_path].size());

  adapters_.insert({adapter_path, adapter});
}

void BluetoothEventServiceImpl::DeviceChanged(
    const dbus::ObjectPath& device_path,
    const BluetoothClient::DeviceProperties& properties) {
  if (!properties.connected.value()) {
    RemoveConnectedDevice(device_path);
    return;
  }

  device_to_adapter_[device_path] = properties.adapter.value();

  const dbus::ObjectPath& adapter_path = properties.adapter.value();
  connected_devices_[adapter_path].insert(device_path);

  UpdateAdapterConnectedDevicesCount(adapter_path);
}

void BluetoothEventServiceImpl::RemoveConnectedDevice(
    const dbus::ObjectPath& device_path) {
  auto device_to_adapter_iter = device_to_adapter_.find(device_path);
  if (device_to_adapter_iter == device_to_adapter_.end()) {
    return;
  }

  const dbus::ObjectPath& adapter_path = device_to_adapter_iter->second;
  auto connected_devices_iter = connected_devices_.find(adapter_path);
  if (connected_devices_iter != connected_devices_.end()) {
    connected_devices_iter->second.erase(device_path);
  }

  device_to_adapter_.erase(device_to_adapter_iter);

  UpdateAdapterConnectedDevicesCount(adapter_path);
}

void BluetoothEventServiceImpl::UpdateAdapterConnectedDevicesCount(
    const dbus::ObjectPath& adapter_path) {
  auto adapters_iter = adapters_.find(adapter_path);
  if (adapters_iter != adapters_.end()) {
    adapters_iter->second.connected_devices_count =
        static_cast<uint32_t>(connected_devices_[adapter_path].size());
  }
}

void BluetoothEventServiceImpl::UpdateAdaptersData() {
  std::vector<AdapterData> new_adapters_data_;
  for (const auto& it : adapters_) {
    new_adapters_data_.push_back(it.second);
  }

  if (last_adapters_data_.size() == new_adapters_data_.size() &&
      std::equal(last_adapters_data_.begin(), last_adapters_data_.end(),
                 new_adapters_data_.begin())) {
    return;
  }

  last_adapters_data_ = std::move(new_adapters_data_);
  for (auto& observer : observers_) {
    observer.BluetoothAdapterDataChanged(last_adapters_data_);
  }
}

}  // namespace wilco
}  // namespace diagnostics
