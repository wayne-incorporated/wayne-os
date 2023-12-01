// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DBUS_OBJECTMANAGER_WRAPPER_H_
#define POWER_MANAGER_POWERD_SYSTEM_DBUS_OBJECTMANAGER_WRAPPER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/compiler_specific.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <brillo/daemons/dbus_daemon.h>
#include <dbus/exported_object.h>
#include <dbus/object_proxy.h>
#include <modemmanager/dbus-proxies.h>

namespace dbus {
class Bus;
}  // namespace dbus

namespace power_manager::system {

using DBusInterfaceToProperties =
    std::map<std::string, brillo::VariantDictionary>;
using DBusObjectsWithProperties =
    std::map<dbus::ObjectPath, DBusInterfaceToProperties>;
using ManagedObjectsCallback =
    base::OnceCallback<void(const DBusObjectsWithProperties&)>;
using InterfacesAddedCallback = base::RepeatingCallback<void(
    const dbus::ObjectPath&,
    const std::map<std::string, brillo::VariantDictionary>&)>;
using InterfacesRemovedCallback = base::RepeatingCallback<void(
    const dbus::ObjectPath&, const std::vector<std::string>&)>;

// These are the methods that a org.freedesktop.DBus.ObjectManager
// proxy must support.  The interface is provided so that it can be
// mocked in tests.  All calls are made asynchronously. Call completion
// is signalled via the callbacks passed to the methods.
class DBusObjectManagerProxyInterface {
 public:
  virtual ~DBusObjectManagerProxyInterface() = default;
  virtual void GetManagedObjects(ManagedObjectsCallback callback) = 0;
  virtual void set_interfaces_added_callback(
      const InterfacesAddedCallback& callback) = 0;
  virtual void set_interfaces_removed_callback(
      const InterfacesRemovedCallback& callback) = 0;
};

class DBusObjectManagerWrapper : public DBusObjectManagerProxyInterface {
 public:
  DBusObjectManagerWrapper(
      const scoped_refptr<dbus::Bus>& bus,
      const std::string& service,
      const std::string& path,
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback
          service_available_callback,
      dbus::ObjectProxy::NameOwnerChangedCallback
          service_owner_changed_callback);
  DBusObjectManagerWrapper(const DBusObjectManagerWrapper&) = delete;
  DBusObjectManagerWrapper& operator=(const DBusObjectManagerWrapper&) = delete;

  ~DBusObjectManagerWrapper() override;
  // Inherited methods from DBusObjectManagerProxyInterface.
  void GetManagedObjects(ManagedObjectsCallback callback) override;

  void set_interfaces_added_callback(
      const InterfacesAddedCallback& callback) override;

  void set_interfaces_removed_callback(
      const InterfacesRemovedCallback& callback) override;

 private:
  std::unique_ptr<org::freedesktop::DBus::ObjectManagerProxy> proxy_;
  base::WeakPtrFactory<DBusObjectManagerWrapper> weak_factory_{this};
};
}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DBUS_OBJECTMANAGER_WRAPPER_H_
