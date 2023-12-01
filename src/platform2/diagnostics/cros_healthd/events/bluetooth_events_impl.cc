// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/bluetooth_events_impl.h"

#include <string>
#include <utility>

#include <base/check.h>

#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

BluetoothEventsImpl::BluetoothEventsImpl(Context* context) {
  DCHECK(context);

  event_subscriptions_.push_back(
      context->bluetooth_event_hub()->SubscribeAdapterAdded(base::BindRepeating(
          &BluetoothEventsImpl::AdapterAdded, weak_ptr_factory_.GetWeakPtr())));
  event_subscriptions_.push_back(
      context->bluetooth_event_hub()->SubscribeAdapterRemoved(
          base::BindRepeating(&BluetoothEventsImpl::AdapterRemoved,
                              weak_ptr_factory_.GetWeakPtr())));
  event_subscriptions_.push_back(
      context->bluetooth_event_hub()->SubscribeAdapterPropertyChanged(
          base::BindRepeating(&BluetoothEventsImpl::AdapterPropertyChanged,
                              weak_ptr_factory_.GetWeakPtr())));
  event_subscriptions_.push_back(
      context->bluetooth_event_hub()->SubscribeDeviceAdded(base::BindRepeating(
          &BluetoothEventsImpl::DeviceAdded, weak_ptr_factory_.GetWeakPtr())));
  event_subscriptions_.push_back(
      context->bluetooth_event_hub()->SubscribeDeviceRemoved(
          base::BindRepeating(&BluetoothEventsImpl::DeviceRemoved,
                              weak_ptr_factory_.GetWeakPtr())));
  event_subscriptions_.push_back(
      context->bluetooth_event_hub()->SubscribeDevicePropertyChanged(
          base::BindRepeating(&BluetoothEventsImpl::DevicePropertyChanged,
                              weak_ptr_factory_.GetWeakPtr())));
}

BluetoothEventsImpl::~BluetoothEventsImpl() {}

void BluetoothEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  observers_.Add(std::move(observer));
}

void BluetoothEventsImpl::AdapterAdded(
    org::bluez::Adapter1ProxyInterface* adapter) {
  mojom::BluetoothEventInfo info;
  info.state = mojom::BluetoothEventInfo::State::kAdapterAdded;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewBluetoothEventInfo(info.Clone()));
}

void BluetoothEventsImpl::AdapterRemoved(const dbus::ObjectPath& adapter_path) {
  mojom::BluetoothEventInfo info;
  info.state = mojom::BluetoothEventInfo::State::kAdapterRemoved;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewBluetoothEventInfo(info.Clone()));
}

void BluetoothEventsImpl::AdapterPropertyChanged(
    org::bluez::Adapter1ProxyInterface* adapter,
    const std::string& property_name) {
  mojom::BluetoothEventInfo info;
  info.state = mojom::BluetoothEventInfo::State::kAdapterPropertyChanged;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewBluetoothEventInfo(info.Clone()));
}

void BluetoothEventsImpl::DeviceAdded(
    org::bluez::Device1ProxyInterface* device) {
  mojom::BluetoothEventInfo info;
  info.state = mojom::BluetoothEventInfo::State::kDeviceAdded;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewBluetoothEventInfo(info.Clone()));
}

void BluetoothEventsImpl::DeviceRemoved(const dbus::ObjectPath& device_path) {
  mojom::BluetoothEventInfo info;
  info.state = mojom::BluetoothEventInfo::State::kDeviceRemoved;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewBluetoothEventInfo(info.Clone()));
}

void BluetoothEventsImpl::DevicePropertyChanged(
    org::bluez::Device1ProxyInterface* device,
    const std::string& property_name) {
  mojom::BluetoothEventInfo info;
  info.state = mojom::BluetoothEventInfo::State::kDevicePropertyChanged;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewBluetoothEventInfo(info.Clone()));
}

}  // namespace diagnostics
