// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_BLUETOOTH_CLIENT_IMPL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_BLUETOOTH_CLIENT_IMPL_H_

#include <string>
#include <vector>

#include <dbus/bus.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <dbus/object_manager.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <dbus/property.h>

#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"

namespace diagnostics {
namespace wilco {

// Adapter for communication with bluetooth daemon.
class BluetoothClientImpl final : public BluetoothClient,
                                  public dbus::ObjectManager::Interface {
 public:
  explicit BluetoothClientImpl(const scoped_refptr<dbus::Bus>& bus);
  ~BluetoothClientImpl() override;

  // BluetoothClient overrides:
  std::vector<dbus::ObjectPath> GetAdapters() override;
  std::vector<dbus::ObjectPath> GetDevices() override;
  const BluetoothClient::AdapterProperties* GetAdapterProperties(
      const dbus::ObjectPath& adapter_path) override;
  const BluetoothClient::DeviceProperties* GetDeviceProperties(
      const dbus::ObjectPath& device_path) override;

  // dbus::ObjectManager::Interface overrides:
  dbus::PropertySet* CreateProperties(
      dbus::ObjectProxy* object_proxy,
      const dbus::ObjectPath& object_path,
      const std::string& interface_name) override;
  void ObjectAdded(const dbus::ObjectPath& object_path,
                   const std::string& interface_name) override;
  void ObjectRemoved(const dbus::ObjectPath& object_path,
                     const std::string& interface_name) override;

 private:
  void PropertyChanged(const dbus::ObjectPath& object_path,
                       const std::string& interface_name,
                       const std::string& property_name);

  // Not owned.
  dbus::ObjectManager* object_manager_;

  base::WeakPtrFactory<BluetoothClientImpl> weak_ptr_factory_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_BLUETOOTH_CLIENT_IMPL_H_
