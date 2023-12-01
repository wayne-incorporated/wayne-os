// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ROUTING_POLICY_ENTRY_H_
#define SHILL_ROUTING_POLICY_ENTRY_H_

// Add for fib_rule_uid_range definition.
#include <linux/fib_rules.h>

#include <optional>
#include <string>

#include "shill/net/ip_address.h"

bool operator==(const fib_rule_uid_range& a, const fib_rule_uid_range& b);

namespace shill {

// Represents a single policy routing rule.
struct RoutingPolicyEntry {
  struct FwMark {
    uint32_t value = 0;
    uint32_t mask = 0xFFFFFFFF;

    bool operator==(const FwMark& b) const {
      return (value == b.value) && (mask == b.mask);
    }
  };

  explicit RoutingPolicyEntry(IPAddress::Family family);

  static RoutingPolicyEntry Create(IPAddress::Family family_in);
  static RoutingPolicyEntry CreateFromSrc(IPAddress src_in);
  static RoutingPolicyEntry CreateFromDst(IPAddress dst_in);

  RoutingPolicyEntry& SetPriority(uint32_t priority_in);
  RoutingPolicyEntry& SetTable(uint32_t table_in);
  RoutingPolicyEntry& SetFwMark(FwMark fw_mark_in);
  // Sets the UID range to contain just a single UID.
  RoutingPolicyEntry& SetUid(uint32_t uid);
  RoutingPolicyEntry& SetUidRange(fib_rule_uid_range uid_range_in);
  RoutingPolicyEntry& SetIif(std::string iif_name_in);
  RoutingPolicyEntry& SetOif(std::string oif_name_in);

  // Flip between IPv4 and v6. |dst| and |src| will only be modified if they
  // have already been set, and will be set to IPAddress(new_ip_family). If
  // |dst| or |src| has been set and is not the default address (all zeros),
  // consider simply creating a new RoutingPolicyEntry using
  // CreateFrom{Src,Dst}.
  RoutingPolicyEntry& FlipFamily();

  bool operator==(const RoutingPolicyEntry& b) const;

  IPAddress::Family family;
  uint32_t priority = 1;
  uint32_t table = RT_TABLE_MAIN;

  IPAddress dst;
  IPAddress src;

  std::optional<FwMark> fw_mark;
  std::optional<fib_rule_uid_range> uid_range;
  std::optional<std::string> iif_name;
  std::optional<std::string> oif_name;

  bool invert_rule = false;
};

}  // namespace shill

#endif  // SHILL_ROUTING_POLICY_ENTRY_H_
