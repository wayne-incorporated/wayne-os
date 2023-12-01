// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_eap_provider.h"

#include <string>
#include <utility>

#include "shill/ethernet/ethernet_eap_service.h"
#include "shill/manager.h"

#include <base/check.h>
#include <base/check_op.h>

namespace shill {

EthernetEapProvider::EthernetEapProvider(Manager* manager)
    : manager_(manager) {}

EthernetEapProvider::~EthernetEapProvider() = default;

void EthernetEapProvider::CreateServicesFromProfile(
    const ProfileRefPtr& profile) {
  // Since the EthernetEapProvider's service is created during Start(),
  // there is no need to do anything in this method.
}

ServiceRefPtr EthernetEapProvider::FindSimilarService(const KeyValueStore& args,
                                                      Error* error) const {
  CHECK_EQ(kTypeEthernetEap, args.Lookup<std::string>(kTypeProperty, ""))
      << "Service type must be Ethernet EAP!";
  return service();
}

ServiceRefPtr EthernetEapProvider::GetService(const KeyValueStore& args,
                                              Error* error) {
  return FindSimilarService(args, error);
}

ServiceRefPtr EthernetEapProvider::CreateTemporaryService(
    const KeyValueStore& args, Error* error) {
  return new EthernetEapService(manager_);
}

ServiceRefPtr EthernetEapProvider::CreateTemporaryServiceFromProfile(
    const ProfileRefPtr& profile, const std::string& entry_name, Error* error) {
  return new EthernetEapService(manager_);
}

void EthernetEapProvider::Start() {
  if (!service_) {
    service_ = new EthernetEapService(manager_);
  }
  manager_->RegisterService(service_);
}

void EthernetEapProvider::Stop() {
  if (service_) {
    manager_->DeregisterService(service_);
  }
  // Do not destroy the service, since devices may or may not have been
  // removed as the provider is stopped, and we'd like them to continue
  // to refer to the same service on restart.
}

void EthernetEapProvider::SetCredentialChangeCallback(
    Ethernet* device, CredentialChangeCallback callback) {
  callback_map_[device] = std::move(callback);
}

void EthernetEapProvider::ClearCredentialChangeCallback(Ethernet* device) {
  CallbackMap::iterator it = callback_map_.find(device);
  if (it != callback_map_.end()) {
    callback_map_.erase(it);
  }
}

void EthernetEapProvider::OnCredentialsChanged() const {
  for (const auto& ethernet_callback_pair : callback_map_) {
    CHECK(!ethernet_callback_pair.second.is_null());
    ethernet_callback_pair.second.Run();
  }
}

}  // namespace shill
