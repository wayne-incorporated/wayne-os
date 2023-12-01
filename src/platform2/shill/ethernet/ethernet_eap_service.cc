// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_eap_service.h"

#include <base/strings/string_number_conversions.h>

#include "shill/eap_credentials.h"
#include "shill/ethernet/ethernet_eap_provider.h"
#include "shill/manager.h"
#include "shill/technology.h"

namespace shill {

EthernetEapService::EthernetEapService(Manager* manager)
    : Service(manager, Technology::kEthernetEap) {
  log_name_ = "etherneteap_" + base::NumberToString(serial_number());
  friendly_name_ = "Ethernet EAP Parameters";
  SetEapCredentials(new EapCredentials());
}

EthernetEapService::~EthernetEapService() = default;

std::string EthernetEapService::GetStorageIdentifier() const {
  return GetTechnologyName() + "_all";
}

RpcIdentifier EthernetEapService::GetDeviceRpcId(Error* /*error*/) const {
  return RpcIdentifier("/");
}

void EthernetEapService::OnEapCredentialsChanged(
    Service::UpdateCredentialsReason reason) {
  if (reason == Service::kReasonPropertyUpdate) {
    // Although the has_ever_connected_ field is not used in the
    // same manner as the other services, we still make this call
    // to maintain consistent behavior by the EAP Credential Change
    // call.
    SetHasEverConnected(false);
  }
  manager()->ethernet_eap_provider()->OnCredentialsChanged();
}

bool EthernetEapService::Unload() {
  Service::Unload();
  manager()->ethernet_eap_provider()->OnCredentialsChanged();
  return false;
}

}  // namespace shill
