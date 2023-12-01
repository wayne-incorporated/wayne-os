// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CONNECTION_H_
#define SHILL_CONNECTION_H_

#include <limits>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/ipconfig.h"
#include "shill/net/ip_address.h"
#include "shill/network/network_priority.h"
#include "shill/routing_table.h"
#include "shill/technology.h"

namespace shill {

class RTNLHandler;
class Resolver;
class RoutingTable;

// The Connection maintains the implemented state of an IPConfig.
// TODO(b/264963034): in progress of migrating to NetworkApplier. Currently
// Connection maintains IPv4 address, routing table and routing policies.

class Connection {
 public:
  Connection(int interface_index,
             const std::string& interface_name,
             bool fixed_ip_params,
             Technology technology);
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;
  virtual ~Connection();

  // Add the contents of an IPConfig::Properties to the list of managed state.
  // This will replace all previous state for this address family. When
  // properties.method == kTypeIPv6, that means that the address is fronm SLAAC
  // therefore address configuration is skipped and Connection only do routing
  // policy setup.
  virtual void UpdateFromIPConfig(const IPConfig::Properties& properties);

  // Routing policy rules have priorities, which establishes the order in which
  // policy rules will be matched against the current traffic. The higher the
  // priority value, the lower the priority of the rule. 0 is the highest rule
  // priority and is generally reserved for the kernel.
  //
  // Updates the kernel's routing policy rule database base on |priority| of
  // current Network, determined by Manager by sorting all Networks.
  virtual void SetPriority(NetworkPriority priority);

  // Flush and (re)create routing policy rules for the connection.
  // Called by Network when it detects address changes (that were not applied
  // through Connection) that need to be reflected in the routing policy rules.
  void UpdateRoutingPolicy(const std::vector<IPAddress>& all_addresses);

  // Return true if this is an IPv6 connection.
  virtual bool IsIPv6();

  virtual const std::string& interface_name() const { return interface_name_; }

 private:
  // The routing rule priority used for the default service, whether physical or
  // VPN.
  static constexpr uint32_t kDefaultPriority = 10;
  // Space between the priorities of services. The Nth highest priority service
  // (starting from N=0) will have a rule priority of
  // |kDefaultPriority| + N*|kPriorityStep|.
  static constexpr uint32_t kPriorityStep = 10;

  // An offset added to the priority of non-VPN services, so their rules comes
  // after the main table rule.
  static constexpr uint32_t kPhysicalPriorityOffset = 1000;

  // Priority for rules corresponding to IPConfig::Properties::routes.
  // Allowed dsts rules are added right before the catchall rule. In this way,
  // existing traffic from a different interface will not be "stolen" by these
  // rules and sent out of the wrong interface, but the routes added to
  // |table_id| will not be ignored.
  static constexpr uint32_t kDstRulePriority =
      RoutingTable::kRulePriorityMain - 3;
  // Priority for VPN rules routing traffic or specific uids with the routing
  // table of a VPN connection.
  static constexpr uint32_t kVpnUidRulePriority =
      RoutingTable::kRulePriorityMain - 2;
  // Priority for the rule sending any remaining traffic to the default physical
  // interface.
  static constexpr uint32_t kCatchallPriority =
      RoutingTable::kRulePriorityMain - 1;

  friend class ConnectionTest;

  // Create a link route to the gateway when the gateway is in a separate
  // subnet. This can work if the host LAN and gateway LAN are bridged together,
  // but is not a recommended network configuration. Return true if |gateway| is
  // reachable or the function successfully installed the route, and false if
  // |gateway| does not exist or the installation failed.
  bool FixGatewayReachability(const IPAddress& local,
                              const std::optional<IPAddress>& gateway);
  // Allow for the routes specified in |properties.routes| to be served by this
  // connection.
  bool SetupIncludedRoutes(const IPConfig::Properties& properties,
                           bool ignore_gateway);
  // Ensure the destination subnets specified in |properties.exclusion_list|
  // will not be served by this connection.
  bool SetupExcludedRoutes(const IPConfig::Properties& properties);
  void SetMTU(int32_t mtu);

  // Flush and (re)create routing policy rules for the connection.
  // The rule priority will be set to |priority_| so that Manager's service
  // sort ranking is respected.
  void UpdateRoutingPolicy();

  // Allow for traffic corresponding to this Connection to match with
  // |table_id|. Note that this does *not* necessarily imply that the traffic
  // will actually be routed through a route in |table_id|. For example, if the
  // traffic matches one of the excluded destination addresses set up in
  // SetupExcludedRoutes, then no routes in the per-Device table for this
  // Connection will be used for that traffic.
  void AllowTrafficThrough(uint32_t table_id,
                           uint32_t base_priority,
                           bool no_ipv6);

  // The priority of the Network calculated by Manager, used to calculate the
  // priority value for setting up routing rules.
  // TODO(b/264963034): remove this cached value in Connection and use the one
  // in Network.
  NetworkPriority priority_;

  int interface_index_;
  const std::string interface_name_;
  Technology technology_;

  // Cache for the addresses added earlier by Connection. Note that current
  // Connection implementation only supports adding at most one IPv4 and one
  // IPv6 address.
  std::map<IPAddress::Family, IPAddress> added_addresses_;
  // All global addresses on the link (IPv4 address from link protocol, or from
  // DHCPv4, or from static IPv4 configuration; and IPv6 address from SLAAC
  // and/or from link protocol). Cached from Network and is only used for
  // setting up routing policy rules.
  std::vector<IPAddress> addresses_for_routing_policy_;

  std::vector<IPAddress> allowed_dsts_;

  // Do not reconfigure the IP addresses, subnet mask, broadcast, etc.
  bool fixed_ip_params_;
  uint32_t table_id_;
  IPAddress local_;
  IPAddress gateway_;

  // Store cached copies of singletons for speed/ease of testing
  RoutingTable* routing_table_;
  RTNLHandler* rtnl_handler_;
};

}  // namespace shill

#endif  // SHILL_CONNECTION_H_
