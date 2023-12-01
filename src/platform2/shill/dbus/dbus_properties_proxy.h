// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DBUS_PROPERTIES_PROXY_H_
#define SHILL_DBUS_DBUS_PROPERTIES_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <brillo/any.h>

#include "shill/error.h"
#include "shill/store/key_value_store.h"

// Using forward declarations to avoid including "cellular/dbus-proxies.h",
// which may inrease the compile time by ~2 seconds by itself.
namespace dbus {
class Bus;
}
namespace org::freedesktop::DBus {
class PropertiesProxyInterface;
}

namespace shill {

// For asynchronous calls, the class instance should outlive the success
// callback invocation since it owns the org::freedesktop::DBus::PropertiesProxy
// object which has an opaque implementation that does not guarantee callback
// completion after destruction.
class DBusPropertiesProxy {
 public:
  // Callback invoked when an object sends a DBus property change signal.
  using PropertiesChangedCallback = base::RepeatingCallback<void(
      const std::string& interface, const KeyValueStore& changed_properties)>;

  DBusPropertiesProxy(const scoped_refptr<dbus::Bus>& bus,
                      const RpcIdentifier& path,
                      const std::string& service);
  DBusPropertiesProxy(const DBusPropertiesProxy&) = delete;
  DBusPropertiesProxy& operator=(const DBusPropertiesProxy&) = delete;

  ~DBusPropertiesProxy();

  KeyValueStore GetAll(const std::string& interface_name);
  void GetAllAsync(
      const std::string& interface_name,
      base::OnceCallback<void(const KeyValueStore&)> success_callback,
      base::OnceCallback<void(const Error&)> error_callback);
  brillo::Any Get(const std::string& interface_name,
                  const std::string& property);
  void GetAsync(const std::string& interface_name,
                const std::string& property,
                base::OnceCallback<void(const brillo::Any&)> success_callback,
                base::OnceCallback<void(const Error&)> error_callback);

  void SetPropertiesChangedCallback(const PropertiesChangedCallback& callback);

  static std::unique_ptr<DBusPropertiesProxy>
  CreateDBusPropertiesProxyForTesting(
      std::unique_ptr<org::freedesktop::DBus::PropertiesProxyInterface> proxy);

  // Only use this with CreateDBusPropertiesProxyForTesting().
  org::freedesktop::DBus::PropertiesProxyInterface*
  GetDBusPropertiesProxyForTesting();

 private:
  // Test only constructor.
  explicit DBusPropertiesProxy(
      std::unique_ptr<org::freedesktop::DBus::PropertiesProxyInterface> proxy);

  // Signal handlers.
  void PropertiesChanged(
      const std::string& interface,
      const brillo::VariantDictionary& changed_properties,
      const std::vector<std::string>& invalidated_properties);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  PropertiesChangedCallback properties_changed_callback_;

  std::unique_ptr<org::freedesktop::DBus::PropertiesProxyInterface> proxy_;

  base::WeakPtrFactory<DBusPropertiesProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_DBUS_PROPERTIES_PROXY_H_
