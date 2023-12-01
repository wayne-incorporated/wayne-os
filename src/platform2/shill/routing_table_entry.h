// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ROUTING_TABLE_ENTRY_H_
#define SHILL_ROUTING_TABLE_ENTRY_H_

#include <linux/rtnetlink.h>

#include <iostream>

#include "shill/net/ip_address.h"

namespace shill {

// Represents a single entry in a routing table.
struct RoutingTableEntry {
  static constexpr int kDefaultTag = -1;

  explicit RoutingTableEntry(IPAddress::Family family);
  RoutingTableEntry(const IPAddress& dst_in,
                    const IPAddress& src_in,
                    const IPAddress& gateway_in);

  static RoutingTableEntry Create(IPAddress::Family family);
  static RoutingTableEntry Create(const IPAddress& dst_in,
                                  const IPAddress& src_in,
                                  const IPAddress& gateway_in);

  RoutingTableEntry& SetMetric(uint32_t metric_in);
  RoutingTableEntry& SetScope(unsigned char scope_in);
  RoutingTableEntry& SetTable(uint32_t table_in);
  RoutingTableEntry& SetType(unsigned char type_in);
  RoutingTableEntry& SetTag(int tag_in);

  bool operator==(const RoutingTableEntry& b) const;

  IPAddress dst;
  IPAddress src;
  IPAddress gateway;
  uint32_t metric = 0;
  unsigned char scope = RT_SCOPE_UNIVERSE;
  uint32_t table = RT_TABLE_MAIN;
  unsigned char type = RTN_UNICAST;
  unsigned char protocol = RTPROT_BOOT;

  // Connections use their interface index as the tag when adding routes, so
  // that as they are destroyed, they can remove all their dependent routes.
  int tag = kDefaultTag;
};

// Print out an entry in a format similar to that of ip route.
std::ostream& operator<<(std::ostream& os, const RoutingTableEntry& entry);

}  // namespace shill

#endif  // SHILL_ROUTING_TABLE_ENTRY_H_
