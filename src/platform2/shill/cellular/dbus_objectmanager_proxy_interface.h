// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_DBUS_OBJECTMANAGER_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_DBUS_OBJECTMANAGER_PROXY_INTERFACE_H_

#include <map>
#include <string>
#include <vector>

#include <base/functional/callback.h>

#include "shill/store/key_value_store.h"

namespace shill {

class Error;

using InterfaceToProperties = std::map<std::string, KeyValueStore>;
using ObjectsWithProperties = std::map<RpcIdentifier, InterfaceToProperties>;
using ManagedObjectsCallback =
    base::OnceCallback<void(const ObjectsWithProperties&, const Error&)>;
using InterfacesAddedSignalCallback = base::RepeatingCallback<void(
    const RpcIdentifier&, const InterfaceToProperties&)>;
using InterfacesRemovedSignalCallback = base::RepeatingCallback<void(
    const RpcIdentifier&, const std::vector<std::string>&)>;

// These are the methods that a org.freedesktop.DBus.ObjectManager
// proxy must support.  The interface is provided so that it can be
// mocked in tests.  All calls are made asynchronously. Call completion
// is signalled via the callbacks passed to the methods.
class DBusObjectManagerProxyInterface {
 public:
  virtual ~DBusObjectManagerProxyInterface() = default;
  virtual void GetManagedObjects(ManagedObjectsCallback callback) = 0;
  virtual void set_interfaces_added_callback(
      const InterfacesAddedSignalCallback& callback) = 0;
  virtual void set_interfaces_removed_callback(
      const InterfacesRemovedSignalCallback& callback) = 0;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_DBUS_OBJECTMANAGER_PROXY_INTERFACE_H_
