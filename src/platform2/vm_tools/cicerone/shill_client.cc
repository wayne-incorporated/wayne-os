// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/shill_client.h"

#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>

using org::chromium::flimflam::ManagerProxy;

namespace vm_tools {
namespace cicerone {

ShillClient::ShillClient(scoped_refptr<dbus::Bus> bus)
    : bus_(bus),
      manager_proxy_(new org::chromium::flimflam::ManagerProxy(bus_)) {
  // The Manager must be watched for changes to the default Service.
  manager_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&ShillClient::OnManagerPropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ShillClient::OnManagerPropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));

  auto owner_changed_cb = base::BindRepeating(
      &ShillClient::OnShillServiceOwnerChange, weak_factory_.GetWeakPtr());
  bus_->GetObjectProxy(shill::kFlimflamServiceName, dbus::ObjectPath{"/"})
      ->SetNameOwnerChangedCallback(owner_changed_cb);
}

void ShillClient::OnShillServiceOwnerChange(const std::string& old_owner,
                                            const std::string& new_owner) {
  std::unique_ptr<ManagerProxy> manager_proxy(new ManagerProxy(bus_));

  manager_proxy_->ReleaseObjectProxy(base::DoNothing());
  manager_proxy->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&ShillClient::OnManagerPropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ShillClient::OnManagerPropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));

  manager_proxy_ = std::move(manager_proxy);
}

void ShillClient::OnManagerPropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  CHECK(success) << "Unable to register for Manager change events";

  brillo::VariantDictionary properties;
  if (!manager_proxy_->GetProperties(&properties, nullptr)) {
    LOG(ERROR) << "Unable to get shill Manager properties";
    return;
  }

  auto it = properties.find(shill::kDefaultServiceProperty);
  CHECK(it != properties.end())
      << "Shill should always publish a default service.";
  OnManagerPropertyChange(shill::kDefaultServiceProperty, it->second);
}

void ShillClient::OnManagerPropertyChange(const std::string& property_name,
                                          const brillo::Any& property_value) {
  // Only handle changes to the default service.
  if (property_name != shill::kDefaultServiceProperty) {
    return;
  }

  if (!default_service_changed_callback_.is_null()) {
    default_service_changed_callback_.Run();
  }
}

void ShillClient::RegisterDefaultServiceChangedHandler(
    base::RepeatingCallback<void()> callback) {
  default_service_changed_callback_ = std::move(callback);
}

}  // namespace cicerone
}  // namespace vm_tools
