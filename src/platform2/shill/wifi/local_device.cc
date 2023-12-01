// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/mac_address.h"
#include "shill/manager.h"
#include "shill/wifi/local_device.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

// Constructor function
LocalDevice::LocalDevice(Manager* manager,
                         IfaceType type,
                         const std::string& link_name,
                         const std::string& mac_address,
                         uint32_t phy_index,
                         const EventCallback& callback)
    : enabled_(false),
      manager_(manager),
      iface_type_(type),
      link_name_(link_name),
      mac_address_(mac_address),
      phy_index_(phy_index),
      callback_(std::move(callback)) {
  SLOG(1) << "LocalDevice(): " << link_name_ << " type: " << iface_type_
          << " MAC address: " << mac_address_ << " Phy index: " << phy_index_;
}

LocalDevice::~LocalDevice() {
  SLOG(1) << "~LocalDevice(): " << link_name_ << " type: " << iface_type_
          << " MAC address: " << mac_address_ << " Phy index: " << phy_index_;
}

bool LocalDevice::SetEnabled(bool enable) {
  if (enabled_ == enable)
    return true;

  LOG(INFO) << (enable ? "Enable " : "Disable ") << "device: " << link_name_;

  if (enable) {
    if (!Start()) {
      LOG(ERROR) << "Failed to start the local device.";
      return false;
    }
  } else {
    Stop();
  }

  enabled_ = enable;
  return true;
}

void LocalDevice::PostDeviceEvent(DeviceEvent event) const {
  SLOG(1) << "Device " << link_name_ << " posts event: " << event;

  manager_->dispatcher()->PostTask(
      FROM_HERE, base::BindOnce(&LocalDevice::DeviceEventTask,
                                weak_factory_.GetWeakPtr(), event));
}

void LocalDevice::DeviceEventTask(DeviceEvent event) const {
  SLOG(1) << "Device " << link_name_ << " handles event: " << event;
  callback_.Run(event, this);
}

EventDispatcher* LocalDevice::Dispatcher() const {
  return manager_->dispatcher();
}

SupplicantProcessProxyInterface* LocalDevice::SupplicantProcessProxy() const {
  return manager_->supplicant_manager()->proxy();
}

ControlInterface* LocalDevice::ControlInterface() const {
  return manager_->control_interface();
}

bool LocalDevice::IsServiceUp() const {
  return GetService() != nullptr && GetService()->IsUp();
}

std::ostream& operator<<(std::ostream& stream, LocalDevice::IfaceType type) {
  if (type == LocalDevice::IfaceType::kAP) {
    stream << "ap";
  } else if (type == LocalDevice::IfaceType::kP2PGO) {
    stream << "p2p_go";
  } else if (type == LocalDevice::IfaceType::kP2PClient) {
    stream << "p2p_client";
  } else {
    stream << "unknown";
  }

  return stream;
}

std::ostream& operator<<(std::ostream& stream, LocalDevice::DeviceEvent event) {
  if (event == LocalDevice::DeviceEvent::kInterfaceDisabled) {
    stream << "InterfaceDisabled";
  } else if (event == LocalDevice::DeviceEvent::kServiceUp) {
    stream << "ServiceUp";
  } else if (event == LocalDevice::DeviceEvent::kServiceDown) {
    stream << "ServiceDown";
  } else if (event == LocalDevice::DeviceEvent::kPeerConnected) {
    stream << "PeerConnected";
  } else if (event == LocalDevice::DeviceEvent::kPeerDisconnected) {
    stream << "PeerDisconnected";
  } else {
    stream << "unknown";
  }

  return stream;
}

}  // namespace shill
