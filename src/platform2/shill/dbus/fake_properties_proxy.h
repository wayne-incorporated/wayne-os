// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_FAKE_PROPERTIES_PROXY_H_
#define SHILL_DBUS_FAKE_PROPERTIES_PROXY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <brillo/any.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/variant_dictionary.h>

#include "cellular/dbus-proxies.h"

namespace shill {

// Fake implementation of Cellular specific PropertiesProxyInterface defined in
// dbus-proxies.h (which is generated from xml files in
// src/third_party/modemmanager-next/introspection/).
// This is used in test implementations of DBusPropertiesProxy to allow testing
// with an actual DBusPropertiesProxy instance but a fake DBus implementation.
class FakePropertiesProxy
    : public org::freedesktop::DBus::PropertiesProxyInterface {
 public:
  FakePropertiesProxy();
  virtual ~FakePropertiesProxy();
  FakePropertiesProxy(const FakePropertiesProxy&) = delete;
  FakePropertiesProxy& operator=(const FakePropertiesProxy&) = delete;

  // PropertiesProxyInterface
  bool Get(const std::string& in_interface_name,
           const std::string& in_property_name,
           brillo::Any* out_value,
           brillo::ErrorPtr* error,
           int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) override;
  void GetAsync(
      const std::string& in_interface_name,
      const std::string& in_property_name,
      base::OnceCallback<void(const brillo::Any& value)> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) override;
  bool Set(const std::string& in_interface_name,
           const std::string& in_property_name,
           const brillo::Any& in_value,
           brillo::ErrorPtr* error,
           int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) override;
  void SetAsync(
      const std::string& in_interface_name,
      const std::string& in_property_name,
      const brillo::Any& in_value,
      base::OnceCallback<void()> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) override;
  bool GetAll(const std::string& in_interface_name,
              brillo::VariantDictionary* out_properties,
              brillo::ErrorPtr* error,
              int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) override;
  void GetAllAsync(
      const std::string& in_interface_name,
      base::OnceCallback<void(const brillo::VariantDictionary& properties)>
          success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) override;
  void RegisterPropertiesChangedSignalHandler(
      const base::RepeatingCallback<void(const std::string&,
                                         const brillo::VariantDictionary&,
                                         const std::vector<std::string>&)>&
          signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override;

  const dbus::ObjectPath& GetObjectPath() const override;
  dbus::ObjectProxy* GetObjectProxy() const override;

  void SetForTesting(const std::string& in_interface_name,
                     const std::string& in_property_name,
                     const brillo::Any& in_value);
  void SetDictionaryForTesting(const std::string& in_interface_name,
                               const brillo::VariantDictionary& in_value);

  static constexpr char kInterfaceNotFound[] = "InterfaceNotFound";
  static constexpr char kPropertyNotFound[] = "PropertyNotFound";

 private:
  bool GetProperty(const std::string& interface,
                   const std::string& property_name,
                   brillo::Any* out_value,
                   std::string* error_code) const;
  bool GetAllProperties(const std::string& interface,
                        brillo::VariantDictionary* out_value) const;

  static constexpr char kDefaultPath[] = "/object/path";
  dbus::ObjectPath path_{kDefaultPath};
  std::map<std::string, brillo::VariantDictionary> properties_;
};

}  // namespace shill

#endif  // SHILL_DBUS_FAKE_PROPERTIES_PROXY_H_
