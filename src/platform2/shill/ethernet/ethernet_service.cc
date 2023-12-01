// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_service.h"

#include <netinet/ether.h>
#include <linux/if.h>  // NOLINT - Needs definitions from netinet/ether.h
#include <stdio.h>
#include <time.h>

#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/dbus/dbus_control.h"
#include "shill/device.h"
#include "shill/device_info.h"
#include "shill/ethernet/ethernet.h"
#include "shill/ethernet/ethernet_provider.h"
#include "shill/manager.h"
#include "shill/profile.h"
#include "shill/store/store_interface.h"

namespace shill {

constexpr char EthernetService::kDefaultEthernetDeviceIdentifier[];

EthernetService::EthernetService(Manager* manager, const Properties& props)
    : EthernetService(manager, Technology::kEthernet, props) {
  SetUp();
}

EthernetService::EthernetService(Manager* manager,
                                 Technology technology,
                                 const Properties& props)
    : Service(manager, technology), props_(props) {}

EthernetService::~EthernetService() {}

void EthernetService::SetUp() {
  log_name_ = "ethernet_" + base::NumberToString(serial_number());
  friendly_name_ = "Ethernet";

  SetConnectable(true);
  SetAutoConnect(true);
  SetStrength(kStrengthMax);

  // Now that |this| is a fully constructed EthernetService, synchronize
  // observers with our current state, and emit the appropriate change
  // notifications. (Initial observer state may have been set in our base
  // class.)
  NotifyIfVisibilityChanged();
}

void EthernetService::OnConnect(Error* /*error*/) {
  if (props_.ethernet_) {
    props_.ethernet_->ConnectTo(this);
  }
}

void EthernetService::OnDisconnect(Error* /*error*/, const char* /*reason*/) {
  if (props_.ethernet_) {
    props_.ethernet_->DisconnectFrom(this);
  }
}

RpcIdentifier EthernetService::GetDeviceRpcId(Error* error) const {
  if (!props_.ethernet_) {
    error->Populate(Error::kNotFound, "Not associated with a device");
    return DBusControl::NullRpcIdentifier();
  }
  return props_.ethernet_->GetRpcIdentifier();
}

std::string EthernetService::GetStorageIdentifier() const {
  if (!props_.ethernet_ || !props_.storage_id_.empty()) {
    return props_.storage_id_;
  }

  const std::string* mac_address = &props_.ethernet_->permanent_mac_address();
  if (mac_address->empty()) {
    mac_address = &props_.ethernet_->mac_address();
  }
  return base::StringPrintf("%s_%s", GetTechnologyName().c_str(),
                            mac_address->c_str());
}

bool EthernetService::IsAutoConnectByDefault() const {
  return true;
}

bool EthernetService::SetAutoConnectFull(const bool& connect, Error* error) {
  if (!connect) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "Auto-connect on Ethernet services must not be disabled.");
    return false;
  }
  return Service::SetAutoConnectFull(connect, error);
}

void EthernetService::Remove(Error* error) {
  error->Populate(Error::kNotImplemented);
}

bool EthernetService::IsVisible() const {
  return props_.ethernet_ && props_.ethernet_->link_up();
}

bool EthernetService::IsAutoConnectable(const char** reason) const {
  if (!Service::IsAutoConnectable(reason)) {
    return false;
  }
  if (!props_.ethernet_ || !props_.ethernet_->link_up()) {
    *reason = Service::kAutoConnMediumUnavailable;
    return false;
  }
  return true;
}

void EthernetService::OnVisibilityChanged() {
  NotifyIfVisibilityChanged();
}

Service::TetheringState EthernetService::GetTethering() const {
  return attached_network() && attached_network()->IsConnectedViaTether()
             ? TetheringState::kConfirmed
             : TetheringState::kNotDetected;
}

}  // namespace shill
