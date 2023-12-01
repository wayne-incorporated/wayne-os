// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/subnet.h"

#include <arpa/inet.h>

#include <string>
#include <utility>

#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

SubnetAddress::SubnetAddress(const net_base::IPv4CIDR& cidr,
                             base::OnceClosure release_cb)
    : cidr_(cidr), release_cb_(std::move(release_cb)) {}

SubnetAddress::~SubnetAddress() = default;

Subnet::Subnet(const net_base::IPv4CIDR& base_cidr,
               base::OnceClosure release_cb)
    : base_cidr_(base_cidr), release_cb_(std::move(release_cb)) {
  addrs_.resize(1ul << (32 - base_cidr_.prefix_length()), false);

  // Mark the base address and broadcast address as allocated.
  CHECK_GE(addrs_.size(), 2);
  addrs_.front() = true;
  addrs_.back() = true;
}

Subnet::~Subnet() = default;

std::unique_ptr<SubnetAddress> Subnet::AllocateAtOffset(uint32_t offset) {
  if (!IsValidOffset(offset)) {
    return nullptr;
  }

  if (addrs_[offset]) {
    // Address is already allocated.
    return nullptr;
  }
  addrs_[offset] = true;

  return std::make_unique<SubnetAddress>(
      *CIDRAtOffset(offset),
      base::BindOnce(&Subnet::Free, weak_factory_.GetWeakPtr(), offset));
}

std::optional<net_base::IPv4CIDR> Subnet::CIDRAtOffset(uint32_t offset) const {
  if (!IsValidOffset(offset)) {
    return std::nullopt;
  }

  return net_base::IPv4CIDR::CreateFromAddressAndPrefix(
      AddOffset(base_cidr_.address(), offset), base_cidr_.prefix_length());
}

uint32_t Subnet::AvailableCount() const {
  // The available IP count is all IPs in a subnet, minus the network ID
  // and the broadcast address.
  return static_cast<uint32_t>(addrs_.size()) - 2;
}

void Subnet::Free(uint32_t offset) {
  DCHECK(IsValidOffset(offset));

  addrs_[offset] = false;
}

bool Subnet::IsValidOffset(uint32_t offset) const {
  // The base address and broadcast address are considered invalid, so the range
  // of the valid offset is (0, addrs_.size() - 1).
  return 0 < offset && offset < addrs_.size() - 1;
}

}  // namespace patchpanel
