// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DBUS_OBJECTMANAGER_PROXY_H_
#define SHILL_DBUS_DBUS_OBJECTMANAGER_PROXY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/dbus_objectmanager_proxy_interface.h"

namespace shill {

class EventDispatcher;

class DBusObjectManagerProxy : public DBusObjectManagerProxyInterface {
 public:
  DBusObjectManagerProxy(
      EventDispatcher* dispatcher,
      const scoped_refptr<dbus::Bus>& bus,
      const RpcIdentifier& path,
      const std::string& service,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback);
  DBusObjectManagerProxy(const DBusObjectManagerProxy&) = delete;
  DBusObjectManagerProxy& operator=(const DBusObjectManagerProxy&) = delete;

  ~DBusObjectManagerProxy() override;

  // Inherited methods from DBusObjectManagerProxyInterface.
  void GetManagedObjects(ManagedObjectsCallback callback) override;

  void set_interfaces_added_callback(
      const InterfacesAddedSignalCallback& callback) override {
    interfaces_added_callback_ = callback;
  }

  void set_interfaces_removed_callback(
      const InterfacesRemovedSignalCallback& callback) override {
    interfaces_removed_callback_ = callback;
  }

 private:
  using DBusInterfaceToProperties =
      std::map<std::string, brillo::VariantDictionary>;
  using DBusObjectsWithProperties =
      std::map<dbus::ObjectPath, DBusInterfaceToProperties>;

  // Signal handlers.
  void InterfacesAdded(
      const dbus::ObjectPath& object_path,
      const DBusInterfaceToProperties& interfaces_and_properties);
  void InterfacesRemoved(const dbus::ObjectPath& object_path,
                         const std::vector<std::string>& interfaces);

  // GetManagedObject method callbacks
  void OnGetManagedObjectsSuccess(
      ManagedObjectsCallback callback,
      const DBusObjectsWithProperties& objects_with_properties);
  void OnGetManagedObjectsFailure(ManagedObjectsCallback callback,
                                  brillo::Error* error);

  // Called when service appeared or vanished.
  void OnServiceAvailable(bool available);

  // Service name owner changed handler.
  void OnServiceOwnerChanged(const std::string& old_owner,
                             const std::string& new_owner);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  void ConvertDBusInterfaceProperties(
      const DBusInterfaceToProperties& dbus_interface_to_properties,
      InterfaceToProperties* interface_to_properties);

  InterfacesAddedSignalCallback interfaces_added_callback_;
  InterfacesRemovedSignalCallback interfaces_removed_callback_;

  std::unique_ptr<org::freedesktop::DBus::ObjectManagerProxy> proxy_;
  EventDispatcher* dispatcher_;
  base::RepeatingClosure service_appeared_callback_;
  base::RepeatingClosure service_vanished_callback_;
  bool service_available_;

  base::WeakPtrFactory<DBusObjectManagerProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_DBUS_OBJECTMANAGER_PROXY_H_
