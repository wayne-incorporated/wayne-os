// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <power_manager/dbus-proxies.h>

#include "libec/ec_usb_device_monitor.h"

namespace ec {

EcUsbDeviceMonitor::EcUsbDeviceMonitor(scoped_refptr<dbus::Bus> bus)
    : power_manager_proxy_(
          std::make_unique<org::chromium::PowerManagerProxy>(bus)) {
  power_manager_proxy_->RegisterSuspendDoneSignalHandler(
      base::BindRepeating(&EcUsbDeviceMonitor::OnSuspendDone,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&EcUsbDeviceMonitor::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
}

void EcUsbDeviceMonitor::OnSuspendDone(
    const std::vector<uint8_t>& serialized_proto) {
  for (auto& observer : observers_) {
    observer.OnDeviceReconnected();
  }
}

void EcUsbDeviceMonitor::OnSignalConnected(const std::string& interface_name,
                                           const std::string& signal_name,
                                           bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

void EcUsbDeviceMonitor::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void EcUsbDeviceMonitor::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

}  // namespace ec
