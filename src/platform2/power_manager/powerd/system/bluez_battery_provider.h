// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_BLUEZ_BATTERY_PROVIDER_H_
#define POWER_MANAGER_POWERD_SYSTEM_BLUEZ_BATTERY_PROVIDER_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <brillo/dbus/exported_object_manager.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_manager.h>

namespace power_manager::system {

// Represents an exported battery object on org.bluez.BatteryProvider1
// interface.
class BluezBattery {
 public:
  BluezBattery(brillo::dbus_utils::ExportedObjectManager* object_manager,
               const scoped_refptr<dbus::Bus>& bus,
               const std::string& address,
               int level,
               const dbus::ObjectPath& object_path,
               const dbus::ObjectPath& device_path);

  // Exports this object to D-Bus.
  void Export(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction callback);

  // Unexports this object from D-Bus.
  void Unexport();

  // Sets the battery level and updates the "Percentage" D-Bus property.
  void SetLevel(int level);

 private:
  brillo::dbus_utils::DBusObject dbus_object_;

  std::string address_;

  brillo::dbus_utils::ExportedProperty<dbus::ObjectPath> device_;
  brillo::dbus_utils::ExportedProperty<uint8_t> percentage_;
};

// Acts as a Battery Provider according to:
// https://chromium.googlesource.com/chromiumos/third_party/bluez/+/refs/heads/chromeos-5.54/doc/battery-api.txt
//
// Summary:
// A BlueZ battery provider starts by registering to BlueZ's
// org.bluez.BatteryProviderManager interface by calling
// RegisterBatteryProvider. After that, it will expose battery objects under
// the registered root path and export the expected properties: Device and
// Percentage. When there is a battery level change, the Percentage property is
// updated and BlueZ will know since it monitors the exported objects.
class BluezBatteryProvider : public dbus::ObjectManager::Interface {
 public:
  BluezBatteryProvider();

  // Initializes the provider.
  void Init(scoped_refptr<dbus::Bus> bus);

  // Resets the state like it was just init-ed.
  void Reset();

  // Notifies about a change in Bluetooth device battery level, or creates one
  // if this is the first notification of the device.
  virtual void UpdateDeviceBattery(const std::string& address, int level);

  // dbus::ObjectManager::Interface overrides:
  // This is to monitor BlueZ's BatteryProviderManager interface presence.
  //
  // When BatteryProviderManager appears, we register as battery provider.
  void ObjectAdded(const dbus::ObjectPath& object_path,
                   const std::string& interface_name) override;
  // When BatteryProviderManager disappears, we reset ourselves to be ready
  // when it appears again.
  void ObjectRemoved(const dbus::ObjectPath& object_path,
                     const std::string& interface_name) override;
  // This is a no-op since there are no properties on BatteryProviderManager.
  dbus::PropertySet* CreateProperties(
      dbus::ObjectProxy* object_proxy,
      const dbus::ObjectPath& object_path,
      const std::string& interface_name) override;

 private:
  void RegisterAsBatteryProvider(dbus::ObjectProxy* manager_proxy);
  void HandleRegisterBatteryProviderResponse(dbus::Response* response);

  BluezBattery* CreateBattery(const std::string& address, int level);
  BluezBattery* GetBattery(const std::string& address);

  scoped_refptr<dbus::Bus> bus_;

  std::unordered_map<std::string, std::unique_ptr<BluezBattery>> batteries_;

  std::unique_ptr<brillo::dbus_utils::ExportedObjectManager>
      battery_exported_object_manager_;

  bool is_registered_ = false;

  dbus::ObjectManager* object_manager_ = nullptr;  // weak

  base::WeakPtrFactory<BluezBatteryProvider> weak_ptr_factory_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_BLUEZ_BATTERY_PROVIDER_H_
