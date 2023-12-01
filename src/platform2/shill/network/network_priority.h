// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_NETWORK_PRIORITY_H_
#define SHILL_NETWORK_NETWORK_PRIORITY_H_

#include <cstdint>
#include <limits>
#include <ostream>

namespace shill {

// A representation of Manager SortServices() result that Network uses to apply
// its configuration accordingly.
struct NetworkPriority {
  static constexpr uint32_t kMaxRankingOrder = 31;
  // Whether current Network is the primary one. Is true for either VPN or the
  // primary physical network if a VPN network is not present.
  bool is_primary_logical = false;
  // Whether current Network is the highest-rank physical network.
  bool is_primary_physical = false;
  // Whether the DNS setting from current network should be set as system
  // default. Is true when all the networks with a higher rank do not have a
  // proper DNS configuration.
  bool is_primary_for_dns = false;
  // A unique value among networks specifying the ranking order of the networks.
  // Primary logical network has a value of 0, secondary network has a value of
  // 1, etc.
  uint32_t ranking_order = kMaxRankingOrder;
};

bool operator==(const NetworkPriority& lhs, const NetworkPriority& rhs);
std::ostream& operator<<(std::ostream& stream, const NetworkPriority& priority);

}  // namespace shill

#endif  // SHILL_NETWORK_NETWORK_PRIORITY_H_
