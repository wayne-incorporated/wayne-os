// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/shill_client.h"

#include <optional>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>

#include "vm_tools/concierge/future.h"

using org::chromium::flimflam::IPConfigProxy;
using org::chromium::flimflam::ServiceProxy;

namespace vm_tools {
namespace concierge {

ShillClient::ShillClient(scoped_refptr<dbus::Bus> bus)
    : bus_(bus),
      manager_proxy_(new org::chromium::flimflam::ManagerProxy(bus_)),
      default_service_proxy_(nullptr),
      default_ipconfig_proxy_(nullptr) {
  // The Manager must be watched for changes to the default Service. To be
  // exact, we are interested in watching changes to the following hierarchy:
  // +----------------+---------------------------+------------------------+
  // |    Manager     |        /service/42        | /ipconfig/eth0_88_dhcp |
  // +----------------+---------------------------+------------------------+
  // | ...            | ...                       | ...                    |
  // | DefaultService | IPConfig:                 | Nameservers: [...]     |
  // |    /service/42 |    /ipconfig/eth0_88_dhcp | SearchDomains: [...]   |
  // | ...            | ...                       | ...                    |
  // +----------------+---------------------------+------------------------+
  //
  // Any change to
  // 1) The Manager's DefaultService,
  // 2) The default Service's IPConfig, or
  // 3) That IPConfig's Nameservers and SearchDomains properties
  // may require updating the nameservers and search domains in the guest VMs.
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
  if (new_owner.empty()) {
    // If shill disappears, clear the cached nameservers and search domains.
    // We'll expect property change signals to come later.
    nameservers_.clear();
    search_domains_.clear();
  }
}

template <typename Proxy>
std::optional<brillo::VariantDictionary> GetPropertiesHelper(dbus::Bus* bus,
                                                             Proxy* proxy) {
  bus->AssertOnOriginThread();
  brillo::VariantDictionary properties;
  if (bus->HasDBusThread()) {
    bool success =
        AsyncNoReject(
            bus->GetDBusTaskRunner(),
            base::BindOnce(
                [](Proxy* proxy, brillo::VariantDictionary* properties) {
                  return proxy->GetProperties(properties, nullptr);
                },
                proxy, &properties))
            .Get()
            .val;
    if (success) {
      return properties;
    }
  } else {
    if (proxy->GetProperties(&properties, nullptr)) {
      return properties;
    }
  }
  return std::nullopt;
}

void ShillClient::OnManagerPropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  CHECK(success) << "Unable to register for Manager change events";

  auto properties = GetPropertiesHelper(bus_.get(), manager_proxy_.get());
  if (!properties) {
    LOG(ERROR) << "Unable to get shill Manager properties";
    return;
  }

  auto it = properties->find(shill::kDefaultServiceProperty);
  CHECK(it != properties->end())
      << "Shill should always publish a default service.";
  OnManagerPropertyChange(shill::kDefaultServiceProperty, it->second);
}

void ShillClient::OnManagerPropertyChange(const std::string& property_name,
                                          const brillo::Any& property_value) {
  // Only handle changes to the default service.
  if (property_name != shill::kDefaultServiceProperty) {
    return;
  }

  dbus::ObjectPath service_path = property_value.TryGet<dbus::ObjectPath>();
  if (!service_path.IsValid() || service_path.value() == "/") {
    // A path of "/" indicates that there is no default service yet. Wait for a
    // future update of the default service property.
    nameservers_.clear();
    search_domains_.clear();
    if (!config_changed_callback_.is_null()) {
      config_changed_callback_.Run(nameservers_, search_domains_);
    }
    return;
  }

  // The default service has changed, so update the proxy object and register
  // a handler for its properties.
  if (default_service_proxy_) {
    default_service_proxy_->ReleaseObjectProxy(base::BindOnce([]() {}));
  }
  default_service_proxy_.reset(new ServiceProxy(bus_, service_path));
  default_service_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&ShillClient::OnServicePropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ShillClient::OnServicePropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));
  if (!default_service_changed_callback_.is_null()) {
    default_service_changed_callback_.Run();
  }
}

void ShillClient::OnServicePropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  CHECK(success) << "Unable to register for Service change events";

  auto properties =
      GetPropertiesHelper(bus_.get(), default_service_proxy_.get());
  if (!properties) {
    LOG(ERROR) << "Unable to get shill Service properties";
    return;
  }

  auto it = properties->find(shill::kIPConfigProperty);
  if (it == properties->end()) {
    return;
  }
  OnServicePropertyChange(shill::kIPConfigProperty, it->second);
}

void ShillClient::OnServicePropertyChange(const std::string& property_name,
                                          const brillo::Any& property_value) {
  if (property_name != shill::kIPConfigProperty) {
    return;
  }

  dbus::ObjectPath ipconfig_path = property_value.TryGet<dbus::ObjectPath>();
  if (!ipconfig_path.IsValid() || ipconfig_path.value() == "/") {
    // A path of "/" indicates that there is no IPConfig yet. Wait for a future
    // update of the IPConfig.
    nameservers_.clear();
    search_domains_.clear();
    if (!config_changed_callback_.is_null()) {
      config_changed_callback_.Run(nameservers_, search_domains_);
    }
    return;
  }

  if (default_ipconfig_proxy_ &&
      default_ipconfig_proxy_->GetObjectPath() == ipconfig_path) {
    // ipconfig path didn't change. Don't need to replace the proxy
    return;
  }

  std::unique_ptr<IPConfigProxy> ipconfig_proxy{
      new IPConfigProxy(bus_, ipconfig_path)};
  auto properties = GetPropertiesHelper(bus_.get(), ipconfig_proxy.get());
  if (!properties) {
    LOG(ERROR) << "Unable to get shill IPConfig properties";
    return;
  }

  auto it = properties->find(shill::kMethodProperty);
  if (it == properties->end()) {
    return;
  }

  // Use it as the default IPConfig for nameservers.
  if (default_ipconfig_proxy_) {
    default_ipconfig_proxy_->ReleaseObjectProxy(base::BindOnce([]() {}));
  }
  default_ipconfig_proxy_ = std::move(ipconfig_proxy);
  default_ipconfig_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&ShillClient::OnIPConfigPropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ShillClient::OnIPConfigPropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));
}

void ShillClient::OnIPConfigPropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  CHECK(success) << "Unable to register for IPConfig change events";

  auto properties =
      GetPropertiesHelper(bus_.get(), default_ipconfig_proxy_.get());
  if (!properties) {
    LOG(ERROR) << "Unable to get shill IPConfig properties";
    return;
  }

  auto ns_it = properties->find(shill::kNameServersProperty);
  if (ns_it != properties->end()) {
    OnIPConfigPropertyChange(shill::kNameServersProperty, ns_it->second);
  }

  auto sd_it = properties->find(shill::kSearchDomainsProperty);
  if (sd_it != properties->end()) {
    OnIPConfigPropertyChange(shill::kSearchDomainsProperty, sd_it->second);
  }
}

void ShillClient::OnIPConfigPropertyChange(const std::string& property_name,
                                           const brillo::Any& property_value) {
  if (property_name != shill::kNameServersProperty &&
      property_name != shill::kSearchDomainsProperty) {
    return;
  }

  if (property_name == shill::kNameServersProperty) {
    std::vector<std::string> new_nameservers{
        property_value.TryGet<std::vector<std::string>>()};
    nameservers_ = std::move(new_nameservers);
  } else {
    std::vector<std::string> new_search_domains{
        property_value.TryGet<std::vector<std::string>>()};
    search_domains_ = std::move(new_search_domains);
  }

  if (!config_changed_callback_.is_null()) {
    config_changed_callback_.Run(nameservers_, search_domains_);
  }
}

void ShillClient::RegisterResolvConfigChangedHandler(
    const base::RepeatingCallback<void(std::vector<std::string>,
                                       std::vector<std::string>)>& callback) {
  config_changed_callback_ = std::move(callback);
  CHECK(!config_changed_callback_.is_null());
  config_changed_callback_.Run(nameservers_, search_domains_);
}

void ShillClient::RegisterDefaultServiceChangedHandler(
    const base::RepeatingCallback<void()>& callback) {
  default_service_changed_callback_ = std::move(callback);
}

}  // namespace concierge
}  // namespace vm_tools
