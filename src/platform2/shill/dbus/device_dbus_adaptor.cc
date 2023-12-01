// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/device_dbus_adaptor.h"

#include <utility>

#include "shill/device.h"
#include "shill/error.h"
#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const DeviceDBusAdaptor* d) {
  return d->GetRpcIdentifier().value() + " (" + d->device()->UniqueName() + ")";
}
}  // namespace Logging

// static
const char DeviceDBusAdaptor::kPath[] = "/device/";

DeviceDBusAdaptor::DeviceDBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
                                     Device* device)
    : org::chromium::flimflam::DeviceAdaptor(this),
      DBusAdaptor(bus, kPath + SanitizePathElement(device->UniqueName())),
      device_(device) {
  // Register DBus object.
  RegisterWithDBusObject(dbus_object());
  dbus_object()->RegisterAndBlock();
}

DeviceDBusAdaptor::~DeviceDBusAdaptor() {
  dbus_object()->UnregisterAndBlock();
  device_ = nullptr;
}

const RpcIdentifier& DeviceDBusAdaptor::GetRpcIdentifier() const {
  return dbus_path();
}

void DeviceDBusAdaptor::EmitBoolChanged(const std::string& name, bool value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitUintChanged(const std::string& name,
                                        uint32_t value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitUint16Changed(const std::string& name,
                                          uint16_t value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitIntChanged(const std::string& name, int value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitStringChanged(const std::string& name,
                                          const std::string& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitStringmapChanged(const std::string& name,
                                             const Stringmap& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitStringmapsChanged(const std::string& name,
                                              const Stringmaps& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitStringsChanged(const std::string& name,
                                           const Strings& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitKeyValueStoreChanged(const std::string& name,
                                                 const KeyValueStore& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(value);
  SendPropertyChangedSignal(name, brillo::Any(dict));
}

void DeviceDBusAdaptor::EmitKeyValueStoresChanged(const std::string& name,
                                                  const KeyValueStores& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  std::vector<brillo::VariantDictionary> dicts;
  for (const auto& element : value) {
    brillo::VariantDictionary dict =
        KeyValueStore::ConvertToVariantDictionary(element);
    dicts.push_back(dict);
  }
  SendPropertyChangedSignal(name, brillo::Any(dicts));
}

void DeviceDBusAdaptor::EmitRpcIdentifierChanged(const std::string& name,
                                                 const RpcIdentifier& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void DeviceDBusAdaptor::EmitRpcIdentifierArrayChanged(
    const std::string& name, const RpcIdentifiers& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  std::vector<dbus::ObjectPath> paths;
  for (const auto& element : value) {
    paths.push_back(dbus::ObjectPath(element));
  }

  SendPropertyChangedSignal(name, brillo::Any(paths));
}

bool DeviceDBusAdaptor::GetProperties(
    brillo::ErrorPtr* error, brillo::VariantDictionary* out_properties) {
  SLOG(this, 2) << __func__;
  return DBusAdaptor::GetProperties(device_->store(), out_properties, error);
}

bool DeviceDBusAdaptor::SetProperty(brillo::ErrorPtr* error,
                                    const std::string& name,
                                    const brillo::Any& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  return DBusAdaptor::SetProperty(device_->mutable_store(), name, value, error);
}

bool DeviceDBusAdaptor::ClearProperty(brillo::ErrorPtr* error,
                                      const std::string& name) {
  SLOG(this, 2) << __func__ << ": " << name;
  return DBusAdaptor::ClearProperty(device_->mutable_store(), name, error);
}

void DeviceDBusAdaptor::Enable(DBusMethodResponsePtr<> response) {
  SLOG(this, 2) << __func__;
  device_->SetEnabledPersistent(true,
                                GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::Disable(DBusMethodResponsePtr<> response) {
  SLOG(this, 2) << __func__ << ": Device " << device_->UniqueName();
  device_->SetEnabledPersistent(false,
                                GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::Register(DBusMethodResponsePtr<> response,
                                 const std::string& network_id) {
  SLOG(this, 2) << __func__ << ": " << network_id;
  device_->RegisterOnNetwork(network_id,
                             GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::RequirePin(DBusMethodResponsePtr<> response,
                                   const std::string& pin,
                                   bool require) {
  SLOG(this, 2) << __func__;

  device_->RequirePin(pin, require,
                      GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::EnterPin(DBusMethodResponsePtr<> response,
                                 const std::string& pin) {
  SLOG(this, 2) << __func__;

  device_->EnterPin(pin, GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::UnblockPin(DBusMethodResponsePtr<> response,
                                   const std::string& unblock_code,
                                   const std::string& pin) {
  SLOG(this, 2) << __func__;

  device_->UnblockPin(unblock_code, pin,
                      GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::ChangePin(DBusMethodResponsePtr<> response,
                                  const std::string& old_pin,
                                  const std::string& new_pin) {
  SLOG(this, 2) << __func__;

  device_->ChangePin(old_pin, new_pin,
                     GetMethodReplyCallback(std::move(response)));
}

void DeviceDBusAdaptor::Reset(DBusMethodResponsePtr<> response) {
  SLOG(this, 2) << __func__;

  device_->Reset(GetMethodReplyCallback(std::move(response)));
}

bool DeviceDBusAdaptor::RequestRoam(brillo::ErrorPtr* error,
                                    const std::string& addr) {
  SLOG(this, 2) << __func__ << ": " << addr;
  Error e;
  device_->RequestRoam(addr, &e);
  return !e.ToChromeosError(error);
}

void DeviceDBusAdaptor::SetUsbEthernetMacAddressSource(
    DBusMethodResponsePtr<> response, const std::string& source) {
  SLOG(this, 2) << __func__;

  device_->SetUsbEthernetMacAddressSource(
      source, GetMethodReplyCallback(std::move(response)));
}

}  // namespace shill
