// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_properties_proxy.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>

#include "cellular/dbus-proxies.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

namespace {

void RunSuccessCallback(
    base::OnceCallback<void(const KeyValueStore&)> success_callback,
    const brillo::VariantDictionary& properties) {
  std::move(success_callback)
      .Run(KeyValueStore::ConvertFromVariantDictionary(properties));
}

void RunErrorCallback(base::OnceCallback<void(const Error&)> error_callback,
                      brillo::Error* dbus_error) {
  std::move(error_callback)
      .Run(Error(Error::kOperationFailed, dbus_error->GetMessage()));
}

}  // namespace

DBusPropertiesProxy::DBusPropertiesProxy(const scoped_refptr<dbus::Bus>& bus,
                                         const RpcIdentifier& path,
                                         const std::string& service)
    : proxy_(new org::freedesktop::DBus::PropertiesProxy(
          bus, service, dbus::ObjectPath(path))) {}

DBusPropertiesProxy::~DBusPropertiesProxy() = default;

// Test only private constructor.
DBusPropertiesProxy::DBusPropertiesProxy(
    std::unique_ptr<org::freedesktop::DBus::PropertiesProxyInterface> proxy)
    : proxy_(std::move(proxy)) {}

// static
std::unique_ptr<DBusPropertiesProxy>
DBusPropertiesProxy::CreateDBusPropertiesProxyForTesting(
    std::unique_ptr<org::freedesktop::DBus::PropertiesProxyInterface> proxy) {
  // Use WrapUnique to allow test constructor to be private.
  return base::WrapUnique(new DBusPropertiesProxy(std::move(proxy)));
}

org::freedesktop::DBus::PropertiesProxyInterface*
DBusPropertiesProxy::GetDBusPropertiesProxyForTesting() {
  return proxy_.get();
}

KeyValueStore DBusPropertiesProxy::GetAll(const std::string& interface_name) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << "(" << interface_name << ")";
  brillo::VariantDictionary properties_dict;
  brillo::ErrorPtr error;
  if (!proxy_->GetAll(interface_name, &properties_dict, &error)) {
    LOG(ERROR) << __func__ << " failed on " << interface_name << ": "
               << error->GetCode() << " " << error->GetMessage();
    return KeyValueStore();
  }
  KeyValueStore properties_store =
      KeyValueStore::ConvertFromVariantDictionary(properties_dict);
  return properties_store;
}

void DBusPropertiesProxy::GetAllAsync(
    const std::string& interface_name,
    base::OnceCallback<void(const KeyValueStore&)> success_callback,
    base::OnceCallback<void(const Error&)> error_callback) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << "(" << interface_name << ")";
  proxy_->GetAllAsync(
      interface_name,
      base::BindOnce(RunSuccessCallback, std::move(success_callback)),
      base::BindOnce(RunErrorCallback, std::move(error_callback)));
}

brillo::Any DBusPropertiesProxy::Get(const std::string& interface_name,
                                     const std::string& property) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << "(" << interface_name << ", " << property << ")";
  brillo::Any value;
  brillo::ErrorPtr error;
  if (!proxy_->Get(interface_name, property, &value, &error)) {
    LOG(ERROR) << __func__ << " failed for " << interface_name << " "
               << property << ": " << error->GetCode() << " "
               << error->GetMessage();
  }
  return value;
}

void DBusPropertiesProxy::GetAsync(
    const std::string& interface_name,
    const std::string& property,
    base::OnceCallback<void(const brillo::Any&)> success_callback,
    base::OnceCallback<void(const Error&)> error_callback) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << "(" << interface_name << ", " << property << ")";
  proxy_->GetAsync(interface_name, property, std::move(success_callback),
                   base::BindOnce(RunErrorCallback, std::move(error_callback)));
}

void DBusPropertiesProxy::SetPropertiesChangedCallback(
    const PropertiesChangedCallback& callback) {
  CHECK(properties_changed_callback_.is_null());
  properties_changed_callback_ = callback;
  proxy_->RegisterPropertiesChangedSignalHandler(
      base::BindRepeating(&DBusPropertiesProxy::PropertiesChanged,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&DBusPropertiesProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
}

void DBusPropertiesProxy::PropertiesChanged(
    const std::string& interface,
    const brillo::VariantDictionary& changed_properties,
    const std::vector<std::string>& /*invalidated_properties*/) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__ << "(" << interface << ")";
  KeyValueStore properties_store =
      KeyValueStore::ConvertFromVariantDictionary(changed_properties);
  properties_changed_callback_.Run(interface, properties_store);
}

void DBusPropertiesProxy::OnSignalConnected(const std::string& interface_name,
                                            const std::string& signal_name,
                                            bool success) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << " success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace shill
