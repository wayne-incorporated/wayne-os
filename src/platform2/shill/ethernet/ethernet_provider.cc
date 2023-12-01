// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_provider.h"

#include "shill/ethernet/ethernet_service.h"
#include "shill/ethernet/ethernet_temporary_service.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/store/store_interface.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/containers/cxx20_erase.h>
#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kEthernet;
}  // namespace Logging

EthernetProvider::EthernetProvider(Manager* manager) : manager_(manager) {}

EthernetProvider::~EthernetProvider() = default;

void EthernetProvider::CreateServicesFromProfile(const ProfileRefPtr& profile) {
  SLOG(2) << __func__;
  // Since the EthernetProvider's service is created during Start(),
  // there is no need to do anything in this method.
}

ServiceRefPtr EthernetProvider::FindSimilarService(const KeyValueStore& args,
                                                   Error* error) const {
  CHECK_EQ(kTypeEthernet, args.Lookup<std::string>(kTypeProperty, ""))
      << "Service type must be Ethernet!";
  ServiceRefPtr service = manager_->GetFirstEthernetService();
  if (service) {
    return service;
  }
  return service_;
}

ServiceRefPtr EthernetProvider::GetService(const KeyValueStore& args,
                                           Error* error) {
  SLOG(2) << __func__;
  return FindSimilarService(args, error);
}

ServiceRefPtr EthernetProvider::CreateTemporaryService(
    const KeyValueStore& args, Error* error) {
  SLOG(2) << __func__;
  return new EthernetTemporaryService(
      manager_, EthernetService::kDefaultEthernetDeviceIdentifier);
}

ServiceRefPtr EthernetProvider::CreateTemporaryServiceFromProfile(
    const ProfileRefPtr& profile, const std::string& entry_name, Error* error) {
  SLOG(2) << __func__;
  return new EthernetTemporaryService(manager_, entry_name);
}

EthernetServiceRefPtr EthernetProvider::CreateService(
    base::WeakPtr<Ethernet> ethernet) {
  SLOG(2) << __func__;
  if (!service_->HasEthernet()) {
    service_->SetEthernet(ethernet);
    return service_;
  }
  return new EthernetService(manager_, EthernetService::Properties(ethernet));
}

void EthernetProvider::RegisterService(EthernetServiceRefPtr service) {
  SLOG(2) << __func__;
  CHECK(service);
  // Add the service to the services_ list and register it with the Manager.
  // A service is registered with the Manager if and only if it is also
  // registered with the EthernetProvider.
  if (base::Contains(services_, service)) {
    LOG(INFO) << "Reusing existing Ethernet service.";
    return;
  }
  services_.push_back(service);
  manager_->RegisterService(service);
}

void EthernetProvider::DeregisterService(EthernetServiceRefPtr service) {
  SLOG(2) << __func__;
  CHECK(service);
  // Remove the service from the services_ list if it is not the only remaining
  // service. Otherwise, turn it into the ethernet_any service. A service is
  // deregistered with the Manager if and only if it is also deregistered with
  // the EthernetProvider.
  CHECK(base::Contains(services_, service))
      << "De-registering an unregistered service";
  if (services_.size() == 1 && service->HasEthernet()) {
    service->ResetEthernet();
    return;
  }
  base::Erase(services_, service);
  manager_->DeregisterService(service);
}

EthernetServiceRefPtr EthernetProvider::FindEthernetServiceForService(
    ServiceRefPtr service) const {
  CHECK(service);
  for (const auto& s : services_) {
    if (s->serial_number() == service->serial_number()) {
      return s;
    }
  }
  return nullptr;
}

bool EthernetProvider::LoadGenericEthernetService() {
  SLOG(2) << __func__;
  return manager_->ActiveProfile()->LoadService(service_);
}

void EthernetProvider::RefreshGenericEthernetService() {
  // Make sure that the first Ethernet service is the generic Ethernet service.
  // This is to ensure that the preferred/default Ethernet service is the one
  // being configured.
  ServiceRefPtr first_ethernet_service = manager_->GetFirstEthernetService();
  CHECK(first_ethernet_service);
  if (first_ethernet_service == service_) {
    return;
  }

  // The first Ethernet service has changed. Remove the ethernet_any storage ID
  // from the old ethernet_any service and configure it according to its new
  // storage ID (MAC address of the associated device). If it has no associated
  // Device, release the service as there should no longer be any other
  // references to it.
  service_->ResetStorageIdentifier();
  if (base::Contains(services_, service_)) {
    if (service_->HasEthernet()) {
      manager_->MatchProfileWithService(service_);
    } else {
      // There's no associated Device and it's no longer the ethernet_any
      // service. Get rid of this service completely.
      DeregisterService(service_);
    }
  }

  // Set the storage ID of the new first Ethernet service to be ethernet_any and
  // configure it accordingly.
  service_ = FindEthernetServiceForService(first_ethernet_service);
  service_->SetStorageIdentifier(
      EthernetService::kDefaultEthernetDeviceIdentifier);
  manager_->MatchProfileWithService(service_);
}

void EthernetProvider::Start() {
  SLOG(2) << __func__;
  // Create a generic Ethernet service with storage ID "ethernet_any". This will
  // be used to store configurations if any are pushed down from Chrome before
  // any Ethernet devices are initialized. This will also be used to persist
  // static IP configurations across Ethernet services.
  if (!service_) {
    service_ = new EthernetService(
        manager_, EthernetService::Properties(
                      EthernetService::kDefaultEthernetDeviceIdentifier));
  }
  RegisterService(service_);
}

void EthernetProvider::Stop() {
  SLOG(2) << __func__;
  while (!services_.empty()) {
    EthernetServiceRefPtr service = services_.back();
    DeregisterService(service);
  }
  // Do not destroy the service, since devices may or may not have been
  // removed as the provider is stopped, and we'd like them to continue
  // to refer to the same service on restart.
}

}  // namespace shill
