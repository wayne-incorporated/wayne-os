// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SUBNET_POOL_H_
#define PATCHPANEL_SUBNET_POOL_H_

#include <stdint.h>

#include <bitset>
#include <memory>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <net-base/ipv4_address.h>

#include "patchpanel/subnet.h"

namespace patchpanel {
constexpr uint32_t kAnySubnetIndex = 0;
constexpr uint32_t kMaxSubnets = 32;

// Manages up to 32 IPv4 subnets that can be assigned to guest interfaces.
// These use non-publicly routable addresses in the range 100.115.92.0/24.
class BRILLO_EXPORT SubnetPool {
 public:
  // Returns a new pool or nullptr if num_subnets exceeds 32.
  static std::unique_ptr<SubnetPool> New(const net_base::IPv4CIDR& base_cidr,
                                         uint32_t num_subnets);
  ~SubnetPool();

  // Allocates and returns a new subnet or nullptr if none are available.
  // |index| may be used to request a particular subnet, it is 1-based so 0
  // indicates no preference.
  std::unique_ptr<Subnet> Allocate(uint32_t index = kAnySubnetIndex);

 private:
  SubnetPool(const net_base::IPv4CIDR& base_cidr, uint32_t num_subnets);
  SubnetPool(const SubnetPool&) = delete;
  SubnetPool& operator=(const SubnetPool&) = delete;

  // Called by Subnets on destruction to free a given subnet.
  void Release(uint32_t index);

  const net_base::IPv4CIDR base_cidr_;
  const uint32_t num_subnets_;
  const uint32_t addr_per_index_;
  std::bitset<kMaxSubnets + 1> subnets_;

  base::WeakPtrFactory<SubnetPool> weak_ptr_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_SUBNET_POOL_H_
