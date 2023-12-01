// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/address_manager.h"

#include <base/logging.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

namespace {

// The 100.115.92.0/24 subnet is reserved and not publicly routable. This subnet
// is sliced into the following IP pools for use among the various usages:
// +---------------+------------+----------------------------------------------+
// |   IP Range    |    Guest   |                                              |
// +---------------+------------+----------------------------------------------+
// | 0       (/30) | ARC/ARCVM  | Used for ARC management interface arc0       |
// | 4-20    (/30) | ARC/ARCVM  | Used to expose multiple host networks to ARC |
// | 24-124  (/30) | Termina VM | Used by Crostini                             |
// | 128-188 (/30) | Host netns | Used for netns hosting minijailed services   |
// | 192-252 (/28) | Containers | Used by Crostini LXD user containers         |
// +---------------+------------+----------------------------------------------+
//
// The 100.115.93.0/24 subnet is reserved for Parallels VMs.

}  // namespace

AddressManager::AddressManager() {
  pools_.emplace(
      GuestType::kArc0,
      SubnetPool::New(
          *net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.0/30"), 1));
  pools_.emplace(
      GuestType::kArcNet,
      SubnetPool::New(
          *net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.4/30"), 5));
  pools_.emplace(
      GuestType::kTerminaVM,
      SubnetPool::New(
          *net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.24/30"), 26));
  pools_.emplace(
      GuestType::kNetns,
      SubnetPool::New(
          *net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.128/30"), 16));
  pools_.emplace(
      GuestType::kLXDContainer,
      SubnetPool::New(
          *net_base::IPv4CIDR::CreateFromCIDRString("100.115.92.192/28"), 4));
  pools_.emplace(
      GuestType::kParallelsVM,
      SubnetPool::New(
          *net_base::IPv4CIDR::CreateFromCIDRString("100.115.93.0/29"), 32));
}

MacAddress AddressManager::GenerateMacAddress(uint32_t index) {
  return index == kAnySubnetIndex ? mac_addrs_.Generate()
                                  : mac_addrs_.GetStable(index);
}

std::unique_ptr<Subnet> AddressManager::AllocateIPv4Subnet(GuestType guest,
                                                           uint32_t index) {
  if (index > 0 && guest != GuestType::kParallelsVM) {
    LOG(ERROR) << "Subnet indexing not supported for guest";
    return nullptr;
  }
  const auto it = pools_.find(guest);
  return (it != pools_.end()) ? it->second->Allocate(index) : nullptr;
}

std::ostream& operator<<(std::ostream& stream,
                         const AddressManager::GuestType guest_type) {
  switch (guest_type) {
    case AddressManager::GuestType::kArc0:
      return stream << "ARC0";
    case AddressManager::GuestType::kArcNet:
      return stream << "ARC_NET";
    case AddressManager::GuestType::kTerminaVM:
      return stream << "TERMINA_VM";
    case AddressManager::GuestType::kParallelsVM:
      return stream << "PARALLELS_VM";
    case AddressManager::GuestType::kLXDContainer:
      return stream << "LXD_CONTAINER";
    case AddressManager::GuestType::kNetns:
      return stream << "MINIJAIL_NETNS";
  }
}

}  // namespace patchpanel
