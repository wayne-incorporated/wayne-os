// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_SYSTEM_SERVICE_PROXY_H_
#define DEBUGD_SRC_HELPERS_SYSTEM_SERVICE_PROXY_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/values.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace debugd {

// Implements a D-Bus proxy to interact with a service on the system bus.
// The typical usage of this class looks like:
//
//    auto proxy = SystemServiceProxy::Create("org.chromium.Service1");
//
//    // To call a method:
//    dbus::MethodCall method("org.chromium.Service1.Interface1", "Method1");
//    auto response = proxy->CallMethodAndGetResponse(
//        dbus::ObjectPath("/org/chromium/Service1/Object1"), &method);
//
//    // To obtain properties:
//    auto properties = proxy->GetProperties(
//        "org.chromium.Service1.Interface2",
//        dbus::ObjectPath("/org/chromium/Service1/Object2"));
//
class SystemServiceProxy {
 public:
  // Creates a D-Bus proxy for the system service identified by |service_name|
  // and connects to the system bus. Returns an instance after it successfully
  // connects to the system bus, or nullptr on error.
  static std::unique_ptr<SystemServiceProxy> Create(
      const std::string& service_name);

  virtual ~SystemServiceProxy() = default;

  // Calls the specified D-Bus method |method_call| on a D-Bus object
  // identified by |object_path| and waits for the response until the default
  // timeout is reached. Returns the response represented as a base::Value or a
  // std::nullopt on error.
  std::optional<base::Value> CallMethodAndGetResponse(
      const dbus::ObjectPath& object_path, dbus::MethodCall* method_call);

  // Gets the properties associated with the interface named |interface_name|
  // of a D-Bus object identified by |object_path|. Returns std::nullopt on
  // error. The implementation provided by this class uses
  // org.freedesktop.DBus.Properties.GetAll to retrieve properties, but a
  // derived class can override this method to use an alternative means to
  // retrieve properties.
  virtual std::optional<base::Value::Dict> GetProperties(
      const std::string& interface_name, const dbus::ObjectPath& object_path);

  // Returns a map from object path to object properties with the interface
  // named |interface_name| for each object listed in |object_paths|.
  base::Value::Dict BuildObjectPropertiesMap(
      const std::string& interface_name,
      const std::vector<dbus::ObjectPath>& object_paths);

  // Gets a list of object paths from a property named |property_name| in the
  // provided property set |properties|. The property is expected to be a list
  // of object paths. Any non-string entry in the list is ignored. If the
  // property isn't found or isn't a list, returns an empty list.
  static std::vector<dbus::ObjectPath> GetObjectPaths(
      const base::Value::Dict& properties, const std::string& property_name);

 protected:
  SystemServiceProxy(scoped_refptr<dbus::Bus> bus,
                     const std::string& service_name);
  SystemServiceProxy(const SystemServiceProxy&) = delete;
  SystemServiceProxy& operator=(const SystemServiceProxy&) = delete;

  // Connects to the system bus. Returns the Bus instance after a successful
  // connection or nullptr on error.
  static scoped_refptr<dbus::Bus> ConnectToSystemBus();

 private:
  scoped_refptr<dbus::Bus> bus_;
  const std::string service_name_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_SYSTEM_SERVICE_PROXY_H_
