// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/virtual_device.h"

#include <netinet/ether.h>
#include <linux/if.h>  // NOLINT - Needs definitions from netinet/ether.h

#include <memory>
#include <string>
#include <utility>

#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/net/rtnl_handler.h"

#include <base/logging.h>

namespace shill {

namespace {
const char kHardwareAddressEmpty[] = "";
}  // namespace

VirtualDevice::VirtualDevice(Manager* manager,
                             const std::string& link_name,
                             int interface_index,
                             Technology technology,
                             bool fixed_ip_params)
    : Device(manager,
             link_name,
             kHardwareAddressEmpty,
             interface_index,
             technology,
             fixed_ip_params) {}

VirtualDevice::~VirtualDevice() = default;

bool VirtualDevice::Load(const StoreInterface* /*storage*/) {
  // Virtual devices have no persistent state.
  return true;
}

bool VirtualDevice::Save(StoreInterface* /*storage*/) {
  // Virtual devices have no persistent state.
  return true;
}

void VirtualDevice::Start(EnabledStateChangedCallback callback) {
  if (!GetPrimaryNetwork()->fixed_ip_params()) {
    rtnl_handler()->SetInterfaceFlags(interface_index(), IFF_UP, IFF_UP);
  }
  std::move(callback).Run(Error(Error::kSuccess));
}

void VirtualDevice::Stop(EnabledStateChangedCallback callback) {
  std::move(callback).Run(Error(Error::kSuccess));
}

void VirtualDevice::UpdateIPConfig(
    std::unique_ptr<IPConfig::Properties> ipv4_properties,
    std::unique_ptr<IPConfig::Properties> ipv6_properties) {
  GetPrimaryNetwork()->set_link_protocol_ipv4_properties(
      std::move(ipv4_properties));
  GetPrimaryNetwork()->set_link_protocol_ipv6_properties(
      std::move(ipv6_properties));
  GetPrimaryNetwork()->Start(Network::StartOptions{
      .dhcp = std::nullopt,
      .accept_ra = false,
      .probing_configuration =
          manager()->GetPortalDetectorProbingConfiguration(),
  });
}

void VirtualDevice::ResetConnection() {
  GetPrimaryNetwork()->Stop();
  Device::SelectService(/*service=*/nullptr, /*reset_old_service_state=*/false);
}

void VirtualDevice::DropConnection() {
  Device::DropConnection();
}

void VirtualDevice::SelectService(const ServiceRefPtr& service) {
  Device::SelectService(service);
}

void VirtualDevice::SetServiceState(Service::ConnectState state) {
  Device::SetServiceState(state);
}

void VirtualDevice::SetServiceFailure(Service::ConnectFailure failure_state) {
  Device::SetServiceFailure(failure_state);
}

void VirtualDevice::SetServiceFailureSilent(
    Service::ConnectFailure failure_state) {
  Device::SetServiceFailureSilent(failure_state);
}

}  // namespace shill
