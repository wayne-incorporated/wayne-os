// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/fake_properties_proxy.h"

#include <utility>

#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/errors/error.h>
#include <brillo/errors/error_codes.h>

namespace shill {

FakePropertiesProxy::FakePropertiesProxy() {}

FakePropertiesProxy::~FakePropertiesProxy() {}

bool FakePropertiesProxy::Get(const std::string& in_interface_name,
                              const std::string& in_property_name,
                              brillo::Any* out_value,
                              brillo::ErrorPtr* error,
                              int timeout_ms) {
  std::string error_code;
  bool res =
      GetProperty(in_interface_name, in_property_name, out_value, &error_code);
  if (!res) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   error_code, "Get failed");
  }
  return res;
}

void FakePropertiesProxy::GetAsync(
    const std::string& in_interface_name,
    const std::string& in_property_name,
    base::OnceCallback<void(const brillo::Any& value)> success_callback,
    base::OnceCallback<void(brillo::Error*)> error_callback,
    int timeout_ms) {
  std::string error_code;
  brillo::Any value;
  if (!GetProperty(in_interface_name, in_property_name, &value, &error_code)) {
    brillo::ErrorPtr error =
        brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                              error_code, "GetAsync failed");
    std::move(error_callback).Run(error.get());
    return;
  }
  std::move(success_callback).Run(value);
}

bool FakePropertiesProxy::Set(const std::string& in_interface_name,
                              const std::string& in_property_name,
                              const brillo::Any& in_value,
                              brillo::ErrorPtr* error,
                              int timeout_ms) {
  properties_[in_interface_name][in_property_name] = in_value;
  return true;
}

void FakePropertiesProxy::SetAsync(
    const std::string& in_interface_name,
    const std::string& in_property_name,
    const brillo::Any& in_value,
    base::OnceCallback<void()> success_callback,
    base::OnceCallback<void(brillo::Error*)> error_callback,
    int timeout_ms) {
  properties_[in_interface_name][in_property_name] = in_value;
  std::move(success_callback).Run();
}

bool FakePropertiesProxy::GetAll(const std::string& in_interface_name,
                                 brillo::VariantDictionary* out_properties,
                                 brillo::ErrorPtr* error,
                                 int timeout_ms) {
  bool res = GetAllProperties(in_interface_name, out_properties);
  if (!res) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   kInterfaceNotFound, "GetAll failed");
  }
  return res;
}

void FakePropertiesProxy::GetAllAsync(
    const std::string& in_interface_name,
    base::OnceCallback<void(const brillo::VariantDictionary& properties)>
        success_callback,
    base::OnceCallback<void(brillo::Error*)> error_callback,
    int timeout_ms) {
  brillo::VariantDictionary dictionary;
  if (!GetAllProperties(in_interface_name, &dictionary)) {
    brillo::ErrorPtr error =
        brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                              kInterfaceNotFound, "GetAllAsync failed");
    std::move(error_callback).Run(error.get());
    return;
  }
  std::move(success_callback).Run(dictionary);
}

void FakePropertiesProxy::RegisterPropertiesChangedSignalHandler(
    const base::RepeatingCallback<void(const std::string&,
                                       const brillo::VariantDictionary&,
                                       const std::vector<std::string>&)>&
        signal_callback,
    dbus::ObjectProxy::OnConnectedCallback on_connected_callback) {}

const dbus::ObjectPath& FakePropertiesProxy::GetObjectPath() const {
  return path_;
}

dbus::ObjectProxy* FakePropertiesProxy::GetObjectProxy() const {
  NOTREACHED();
  return nullptr;
}

void FakePropertiesProxy::SetForTesting(const std::string& in_interface_name,
                                        const std::string& in_property_name,
                                        const brillo::Any& in_value) {
  properties_[in_interface_name][in_property_name] = in_value;
}

void FakePropertiesProxy::SetDictionaryForTesting(
    const std::string& in_interface_name,
    const brillo::VariantDictionary& in_value) {
  properties_[in_interface_name] = in_value;
}

bool FakePropertiesProxy::GetProperty(const std::string& interface,
                                      const std::string& property_name,
                                      brillo::Any* out_value,
                                      std::string* error_code) const {
  auto iter1 = properties_.find(interface);
  if (iter1 == properties_.end()) {
    LOG(ERROR) << "Get: Interface not found: " << interface;
    *error_code = kInterfaceNotFound;
    return false;
  }
  auto iter2 = iter1->second.find(property_name);
  if (iter2 == iter1->second.end()) {
    LOG(ERROR) << "Get: Property not found: " << interface << ": "
               << property_name;
    *error_code = kPropertyNotFound;
    return false;
  }
  *out_value = iter2->second;
  return true;
}

bool FakePropertiesProxy::GetAllProperties(
    const std::string& interface, brillo::VariantDictionary* out_value) const {
  auto iter1 = properties_.find(interface);
  if (iter1 == properties_.end()) {
    LOG(ERROR) << "GetAll: Interface not found: " << interface;
    return false;
  }
  *out_value = iter1->second;
  return true;
}

}  // namespace shill
