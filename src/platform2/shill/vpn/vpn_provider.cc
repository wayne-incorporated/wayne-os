// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_provider.h"

#include <algorithm>
#include <map>
#include <memory>
#include <utility>

#include <base/containers/fixed_flat_map.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/process_manager.h"
#include "shill/profile.h"
#include "shill/routing_policy_entry.h"
#include "shill/store/store_interface.h"
#include "shill/vpn/arc_vpn_driver.h"
#include "shill/vpn/ikev2_driver.h"
#include "shill/vpn/l2tp_ipsec_driver.h"
#include "shill/vpn/openvpn_driver.h"
#include "shill/vpn/third_party_vpn_driver.h"
#include "shill/vpn/vpn_service.h"
#include "shill/vpn/wireguard_driver.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kVPN;
}  // namespace Logging

namespace {

// Populates |type_ptr|, |name_ptr| and |host_ptr| with the appropriate
// values from |args|.  Returns True on success, otherwise if any of
// these arguments are not available, |error| is populated and False is
// returned.
bool GetServiceParametersFromArgs(const KeyValueStore& args,
                                  std::string* type_ptr,
                                  std::string* name_ptr,
                                  std::string* host_ptr,
                                  Error* error) {
  SLOG(2) << __func__;
  const auto type = args.Lookup<std::string>(kProviderTypeProperty, "");
  if (type.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidProperty,
                          "Missing VPN type property.");
    return false;
  }

  const auto host = args.Lookup<std::string>(kProviderHostProperty, "");
  if (host.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidProperty,
                          "Missing VPN host property.");
    return false;
  }

  *type_ptr = type;
  *host_ptr = host;
  *name_ptr = args.Lookup<std::string>(kNameProperty, "");

  return true;
}

// Populates |vpn_type_ptr|, |name_ptr| and |host_ptr| with the appropriate
// values from profile storgae.  Returns True on success, otherwise if any of
// these arguments are not available, |error| is populated and False is
// returned.
bool GetServiceParametersFromStorage(const StoreInterface* storage,
                                     const std::string& entry_name,
                                     std::string* vpn_type_ptr,
                                     std::string* name_ptr,
                                     std::string* host_ptr,
                                     Error* error) {
  std::string service_type;
  if (!storage->GetString(entry_name, kTypeProperty, &service_type) ||
      service_type != kTypeVPN) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Unspecified or invalid network type");
    return false;
  }

  if (!storage->GetString(entry_name, kProviderTypeProperty, vpn_type_ptr) ||
      vpn_type_ptr->empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "VPN type not specified");
    return false;
  }

  if (!storage->GetString(entry_name, kNameProperty, name_ptr) ||
      name_ptr->empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Network name not specified");
    return false;
  }

  if (!storage->GetString(entry_name, kProviderHostProperty, host_ptr) ||
      host_ptr->empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Host not specified");
    return false;
  }
  return true;
}

}  // namespace

// static
std::optional<VPNType> VPNProvider::VPNTypeStringToEnum(
    base::StringPiece type) {
  static constexpr auto dict =
      base::MakeFixedFlatMap<base::StringPiece, VPNType>({
          {kProviderArcVpn, VPNType::kARC},
          {kProviderIKEv2, VPNType::kIKEv2},
          {kProviderL2tpIpsec, VPNType::kL2TPIPsec},
          {kProviderOpenVpn, VPNType::kOpenVPN},
          {kProviderThirdPartyVpn, VPNType::kThirdParty},
          {kProviderWireGuard, VPNType::kWireGuard},
      });
  const auto it = dict.find(type);
  if (it == dict.end()) {
    return std::nullopt;
  }
  return it->second;
}

// static
std::string VPNProvider::VPNTypeEnumToString(VPNType type) {
  switch (type) {
    case VPNType::kARC:
      return kProviderArcVpn;
    case VPNType::kIKEv2:
      return kProviderIKEv2;
    case VPNType::kL2TPIPsec:
      return kProviderL2tpIpsec;
    case VPNType::kOpenVPN:
      return kProviderOpenVpn;
    case VPNType::kThirdParty:
      return kProviderThirdPartyVpn;
    case VPNType::kWireGuard:
      return kProviderWireGuard;
  }
  NOTREACHED();
  return "";
}

VPNProvider::VPNProvider(Manager* manager) : manager_(manager) {}

VPNProvider::~VPNProvider() = default;

void VPNProvider::Start() {}

void VPNProvider::Stop() {}

ServiceRefPtr VPNProvider::GetService(const KeyValueStore& args, Error* error) {
  SLOG(2) << __func__;
  std::string type;
  std::string name;
  std::string host;

  if (!GetServiceParametersFromArgs(args, &type, &name, &host, error)) {
    return nullptr;
  }

  const auto storage_id = VPNService::CreateStorageIdentifier(args, error);
  if (storage_id.empty()) {
    return nullptr;
  }

  // Find a service in the provider list which matches these parameters.
  VPNServiceRefPtr service = FindService(type, name, host);
  if (service == nullptr) {
    service = CreateService(type, name, storage_id, error);
  }
  return service;
}

ServiceRefPtr VPNProvider::FindSimilarService(const KeyValueStore& args,
                                              Error* error) const {
  SLOG(2) << __func__;
  std::string type;
  std::string name;
  std::string host;

  if (!GetServiceParametersFromArgs(args, &type, &name, &host, error)) {
    return nullptr;
  }

  // Find a service in the provider list which matches these parameters.
  VPNServiceRefPtr service = FindService(type, name, host);
  if (!service) {
    error->Populate(Error::kNotFound, Error::kServiceNotFoundMsg, FROM_HERE);
  }

  return service;
}

void VPNProvider::RemoveService(VPNServiceRefPtr service) {
  const auto it = std::find(services_.begin(), services_.end(), service);
  if (it != services_.end()) {
    services_.erase(it);
  }
}

void VPNProvider::CreateServicesFromProfile(const ProfileRefPtr& profile) {
  SLOG(2) << __func__;
  const StoreInterface* storage = profile->GetConstStorage();
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeVPN);
  for (const auto& group : storage->GetGroupsWithProperties(args)) {
    std::string type;
    std::string name;
    std::string host;
    if (!GetServiceParametersFromStorage(storage, group, &type, &name, &host,
                                         nullptr)) {
      continue;
    }

    VPNServiceRefPtr service = FindService(type, name, host);
    if (service != nullptr) {
      // If the service already exists, it does not need to be configured,
      // since PushProfile would have already called ConfigureService on it.
      SLOG(2) << "Service already exists " << group;
      continue;
    }

    Error error;
    service = CreateService(type, name, group, &error);

    if (service == nullptr) {
      LOG(ERROR) << "Could not create service for " << group;
      continue;
    }

    if (!profile->ConfigureService(service)) {
      LOG(ERROR) << "Could not configure service for " << group;
      continue;
    }
  }
}

VPNServiceRefPtr VPNProvider::CreateServiceInner(const std::string& type,
                                                 const std::string& name,
                                                 const std::string& storage_id,
                                                 Error* error) {
  SLOG(2) << __func__ << " type " << type << " name " << name << " storage id "
          << storage_id;
#if defined(DISABLE_VPN)

  Error::PopulateAndLog(FROM_HERE, error, Error::kTechnologyNotAvailable,
                        "VPN technology is not available.");
  return nullptr;

#else

  std::unique_ptr<VPNDriver> driver;
  if (type == kProviderOpenVpn) {
    driver.reset(new OpenVPNDriver(manager_, ProcessManager::GetInstance()));
  } else if (type == kProviderL2tpIpsec) {
    driver.reset(new L2TPIPsecDriver(manager_, ProcessManager::GetInstance()));
  } else if (type == kProviderIKEv2) {
    driver.reset(new IKEv2Driver(manager_, ProcessManager::GetInstance()));
  } else if (type == kProviderThirdPartyVpn) {
    // For third party VPN host contains extension ID
    driver.reset(
        new ThirdPartyVpnDriver(manager_, ProcessManager::GetInstance()));
  } else if (type == kProviderArcVpn) {
    driver.reset(new ArcVpnDriver(manager_, ProcessManager::GetInstance()));
  } else if (type == kProviderWireGuard) {
    driver.reset(new WireGuardDriver(manager_, ProcessManager::GetInstance()));
  } else {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "Invalid VPN type: " + type);
    return nullptr;
  }

  VPNServiceRefPtr service = new VPNService(manager_, std::move(driver));
  service->set_storage_id(storage_id);
  service->InitDriverPropertyStore();
  if (!name.empty()) {
    service->SetFriendlyName(name);
  }
  return service;

#endif  // DISABLE_VPN
}

VPNServiceRefPtr VPNProvider::CreateService(const std::string& type,
                                            const std::string& name,
                                            const std::string& storage_id,
                                            Error* error) {
  VPNServiceRefPtr service = CreateServiceInner(type, name, storage_id, error);
  if (service) {
    services_.push_back(service);
    manager_->RegisterService(service);
  }

  return service;
}

VPNServiceRefPtr VPNProvider::FindService(const std::string& type,
                                          const std::string& name,
                                          const std::string& host) const {
  const auto vpn_type = VPNTypeStringToEnum(type);
  if (!vpn_type) {
    LOG(WARNING) << "Invalid VPN type " << type;
    return nullptr;
  }
  for (const auto& service : services_) {
    if (*vpn_type == service->driver()->vpn_type() &&
        name == service->friendly_name() &&
        host == service->driver()->GetHost()) {
      return service;
    }
  }
  return nullptr;
}

ServiceRefPtr VPNProvider::CreateTemporaryService(const KeyValueStore& args,
                                                  Error* error) {
  std::string type;
  std::string name;
  std::string host;

  if (!GetServiceParametersFromArgs(args, &type, &name, &host, error)) {
    return nullptr;
  }

  const std::string storage_id =
      VPNService::CreateStorageIdentifier(args, error);
  if (storage_id.empty()) {
    return nullptr;
  }

  return CreateServiceInner(type, name, storage_id, error);
}

ServiceRefPtr VPNProvider::CreateTemporaryServiceFromProfile(
    const ProfileRefPtr& profile, const std::string& entry_name, Error* error) {
  std::string type;
  std::string name;
  std::string host;
  if (!GetServiceParametersFromStorage(profile->GetConstStorage(), entry_name,
                                       &type, &name, &host, error)) {
    return nullptr;
  }

  return CreateServiceInner(type, name, entry_name, error);
}

bool VPNProvider::HasActiveService() const {
  for (const auto& service : services_) {
    if (service->IsConnecting() || service->IsConnected()) {
      return true;
    }
  }
  return false;
}

void VPNProvider::DisconnectAll() {
  for (const auto& service : services_) {
    if (service->IsConnecting() || service->IsConnected()) {
      service->Disconnect(nullptr, "user selected new config");
    }
  }
}

std::string VPNProvider::GetSupportedType() {
#ifndef DISABLE_VPN
  std::vector<std::string> list({kProviderL2tpIpsec, kProviderOpenVpn,
                                 kProviderThirdPartyVpn, kProviderArcVpn});
  if (IKEv2Driver::IsSupported()) {
    list.push_back(kProviderIKEv2);
  }
  if (WireGuardDriver::IsSupported()) {
    list.push_back(kProviderWireGuard);
  }
  return base::JoinString(list, ",");
#else
  return "";
#endif  // DISABLE_VPN
}

}  // namespace shill
