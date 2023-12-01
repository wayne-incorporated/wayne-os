// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/subnet_pool.h"

#include <arpa/inet.h>

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/stringprintf.h>

#include "patchpanel/net_util.h"

using std::string;

namespace patchpanel {

// static
std::unique_ptr<SubnetPool> SubnetPool::New(const net_base::IPv4CIDR& base_cidr,
                                            uint32_t num_subnets) {
  if (base_cidr.GetPrefixAddress() != base_cidr.address()) {
    LOG(ERROR) << "base_cidr doesn't contain the base address: " << base_cidr;
    return nullptr;
  }
  if (num_subnets > kMaxSubnets) {
    LOG(ERROR) << "Maximum subnets supported is " << kMaxSubnets << "; got "
               << num_subnets;
    return nullptr;
  }
  return base::WrapUnique(new SubnetPool(base_cidr, num_subnets));
}

SubnetPool::SubnetPool(const net_base::IPv4CIDR& base_cidr,
                       uint32_t num_subnets)
    : base_cidr_(base_cidr),
      num_subnets_(num_subnets),
      addr_per_index_(1 << (net_base::IPv4CIDR::kMaxPrefixLength -
                            base_cidr_.prefix_length())) {
  subnets_.set(0);  // unused.
}

SubnetPool::~SubnetPool() {
  subnets_.reset(0);
  if (subnets_.any()) {
    LOG(ERROR) << "SubnetPool destroyed with unreleased subnets";
  }
}

std::unique_ptr<Subnet> SubnetPool::Allocate(uint32_t index) {
  if (index == 0) {
    while (index <= num_subnets_ && subnets_.test(index)) {
      ++index;
    }
  }

  if (index > num_subnets_) {
    LOG(ERROR) << "Desired index (" << index << ") execeeds number of"
               << " available subnets (" << num_subnets_ << ")";
    return nullptr;
  }
  if (subnets_.test(index)) {
    LOG(WARNING) << "Subnet at index (" << index << ") is unavailable";
    return nullptr;
  }

  subnets_.set(index);
  const auto subnet_cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
      AddOffset(base_cidr_.address(), (index - 1) * addr_per_index_),
      base_cidr_.prefix_length());
  return std::make_unique<Subnet>(
      subnet_cidr, base::BindOnce(&SubnetPool::Release,
                                  weak_ptr_factory_.GetWeakPtr(), index));
}

void SubnetPool::Release(uint32_t index) {
  if (index == 0) {
    LOG(DFATAL) << "Invalid index value: 0";
    return;
  }
  DCHECK(subnets_.test(index));
  subnets_.reset(index);
}

}  // namespace patchpanel
