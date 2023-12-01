// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_temporary_service.h"

#include "shill/dbus/dbus_control.h"
#include "shill/manager.h"

namespace shill {

EthernetTemporaryService::EthernetTemporaryService(
    Manager* manager, const std::string& storage_identifier)
    : Service(manager, Technology::kEthernet),
      storage_identifier_(storage_identifier) {
  friendly_name_ = "Ethernet";
}

EthernetTemporaryService::~EthernetTemporaryService() = default;

RpcIdentifier EthernetTemporaryService::GetDeviceRpcId(Error* /*error*/) const {
  return DBusControl::NullRpcIdentifier();
}

std::string EthernetTemporaryService::GetStorageIdentifier() const {
  return storage_identifier_;
}

bool EthernetTemporaryService::IsVisible() const {
  return false;
}

}  // namespace shill
