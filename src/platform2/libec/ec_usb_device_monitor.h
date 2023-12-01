// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_EC_USB_DEVICE_MONITOR_H_
#define LIBEC_EC_USB_DEVICE_MONITOR_H_

#include <memory>
#include <string>
#include <vector>

#include <base/observer_list_types.h>
#include <base/observer_list.h>
#include <brillo/brillo_export.h>

#include <power_manager/dbus-proxies.h>

namespace ec {

// Monitors for when EC USB Device has been reconnected and informs observers.
// Currently, this class only informs observers after device is woken up from
// suspend.
class BRILLO_EXPORT EcUsbDeviceMonitor {
 public:
  explicit EcUsbDeviceMonitor(scoped_refptr<dbus::Bus> bus);

  EcUsbDeviceMonitor(const EcUsbDeviceMonitor&) = delete;
  EcUsbDeviceMonitor& operator=(const EcUsbDeviceMonitor&) = delete;

  class Observer : public base::CheckedObserver {
   public:
    virtual void OnDeviceReconnected() = 0;
  };

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  void OnSuspendDone(const std::vector<uint8_t>& serialized_proto);
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

 private:
  base::ObserverList<Observer> observers_;
  std::unique_ptr<org::chromium::PowerManagerProxy> power_manager_proxy_;
  base::WeakPtrFactory<EcUsbDeviceMonitor> weak_factory_{this};
};

}  // namespace ec

#endif  // LIBEC_EC_USB_DEVICE_MONITOR_H_
