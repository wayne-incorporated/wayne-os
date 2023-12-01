// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/connection.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <unistd.h>

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/shill/dbus-constants.h>

#include "shill/logging.h"
#include "shill/net/ip_address.h"
#include "shill/net/rtnl_handler.h"
#include "shill/network/network_priority.h"
#include "shill/routing_table.h"
#include "shill/routing_table_entry.h"
#include "shill/technology.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kConnection;
static std::string ObjectID(const Connection* c) {
  if (c == nullptr)
    return "(connection)";
  return c->interface_name();
}
}  // namespace Logging

namespace {

// TODO(b/161507671) Use the constants defined in patchpanel::RoutingService at
// platform2/patchpanel/routing_service.cc after the routing layer is migrated
// to patchpanel.
constexpr const uint32_t kFwmarkRoutingMask = 0xffff0000;

RoutingPolicyEntry::FwMark GetFwmarkRoutingTag(int interface_index) {
  return {.value = RoutingTable::GetInterfaceTableId(interface_index) << 16,
          .mask = kFwmarkRoutingMask};
}

}  // namespace

Connection::Connection(int interface_index,
                       const std::string& interface_name,
                       bool fixed_ip_params,
                       Technology technology)
    : interface_index_(interface_index),
      interface_name_(interface_name),
      technology_(technology),
      fixed_ip_params_(fixed_ip_params),
      table_id_(RoutingTable::GetInterfaceTableId(interface_index)),
      local_(IPAddress::CreateFromFamily(IPAddress::kFamilyUnknown)),
      gateway_(IPAddress::CreateFromFamily(IPAddress::kFamilyUnknown)),
      routing_table_(RoutingTable::GetInstance()),
      rtnl_handler_(RTNLHandler::GetInstance()) {
  SLOG(this, 2) << __func__ << "(" << interface_index << ", " << interface_name
                << ", " << technology << ")";
}

Connection::~Connection() {
  SLOG(this, 2) << __func__ << " " << interface_name_;

  routing_table_->FlushRoutes(interface_index_);
  routing_table_->FlushRoutesWithTag(interface_index_);
  if (!fixed_ip_params_) {
    for (const auto& [family, addr] : added_addresses_) {
      rtnl_handler_->RemoveInterfaceAddress(interface_index_, addr);
    }
  }
  routing_table_->FlushRules(interface_index_);
}

bool Connection::SetupIncludedRoutes(const IPConfig::Properties& properties,
                                     bool ignore_gateway) {
  bool ret = true;

  IPAddress::Family address_family = properties.address_family;

  // Merge the routes to be installed from |dhcp_classless_static_routes| and
  // |inclusion_list|.
  std::vector<IPConfig::Route> included_routes =
      properties.dhcp_classless_static_routes;
  for (const auto& prefix_cidr : properties.inclusion_list) {
    const auto prefix =
        IPAddress::CreateFromPrefixString(prefix_cidr, address_family);
    if (!prefix.has_value()) {
      LOG(ERROR) << "Failed to parse prefix " << prefix_cidr;
      ret = false;
      continue;
    }
    IPConfig::Route route;
    prefix->IntoString(&route.host);
    route.prefix = prefix->prefix();
    route.gateway = properties.gateway;
    if (route.gateway.empty()) {
      // Gateway address with all-zeros indicates this route does not have a
      // gateway.
      route.gateway =
          (address_family == IPAddress::kFamilyIPv4) ? "0.0.0.0" : "::";
    }
    included_routes.push_back(route);
  }

  for (const auto& route : included_routes) {
    SLOG(this, 2) << "Installing route:"
                  << " Destination: " << route.host
                  << " Prefix: " << route.prefix
                  << " Gateway: " << route.gateway;
    const auto dst = IPAddress::CreateFromStringAndPrefix(
        route.host, route.prefix, address_family);
    if (!dst.has_value()) {
      LOG(ERROR) << "Failed to parse host " << route.host;
      ret = false;
      continue;
    }

    auto gateway = IPAddress::CreateFromString(route.gateway, address_family);
    if (!gateway.has_value()) {
      LOG(ERROR) << "Failed to parse gateway " << route.gateway;
      ret = false;
      continue;
    }
    if (ignore_gateway) {
      gateway->SetAddressToDefault();
    }

    // Left as default.
    const auto src = IPAddress::CreateFromFamily_Deprecated(address_family);

    if (!routing_table_->AddRoute(interface_index_,
                                  RoutingTableEntry::Create(*dst, src, *gateway)
                                      .SetTable(table_id_)
                                      .SetTag(interface_index_))) {
      ret = false;
    }
  }
  return ret;
}

bool Connection::SetupExcludedRoutes(const IPConfig::Properties& properties) {
  // If this connection has its own dedicated routing table, exclusion
  // is as simple as adding an RTN_THROW entry for each item on the list.
  // Traffic that matches the RTN_THROW entry will cause the kernel to
  // stop traversing our routing table and try the next rule in the list.
  IPAddress empty_ip =
      IPAddress::CreateFromFamily_Deprecated(properties.address_family);
  auto entry = RoutingTableEntry::Create(empty_ip, empty_ip, empty_ip)
                   .SetScope(RT_SCOPE_LINK)
                   .SetTable(table_id_)
                   .SetType(RTN_THROW)
                   .SetTag(interface_index_);
  for (const auto& excluded_ip : properties.exclusion_list) {
    auto dst = IPAddress::CreateFromPrefixString(excluded_ip,
                                                 properties.address_family);
    if (!dst.has_value()) {
      LOG(ERROR) << "Excluded prefix is invalid: " << excluded_ip;
      return false;
    }
    entry.dst = std::move(*dst);
    if (!routing_table_->AddRoute(interface_index_, entry)) {
      LOG(ERROR) << "Unable to setup route for " << excluded_ip;
      return false;
    }
  }
  return true;
}

void Connection::UpdateFromIPConfig(const IPConfig::Properties& properties) {
  SLOG(this, 2) << __func__ << " " << interface_name_;

  allowed_dsts_.clear();
  for (const auto& route : properties.dhcp_classless_static_routes) {
    const auto dst =
        IPAddress::CreateFromStringAndPrefix(route.host, route.prefix);
    if (!dst.has_value()) {
      LOG(ERROR) << "Failed to parse static route address " << route.host;
      continue;
    }
    allowed_dsts_.push_back(*dst);
  }

  std::optional<IPAddress> gateway;
  if (!properties.gateway.empty()) {
    gateway = IPAddress::CreateFromString(properties.gateway);
    if (!gateway.has_value()) {
      LOG(ERROR) << "Gateway address " << properties.gateway << " is invalid";
      return;
    }
  }

  const auto local = IPAddress::CreateFromStringAndPrefix(
      properties.address, properties.subnet_prefix, properties.address_family);
  if (!local.has_value()) {
    LOG(ERROR) << "Local address " << properties.address << " is invalid";
    return;
  }

  std::optional<IPAddress> broadcast;
  if (properties.broadcast_address.empty()) {
    if (local->family() == IPAddress::kFamilyIPv4 &&
        properties.peer_address.empty()) {
      LOG(WARNING) << "Broadcast address is not set.  Using default.";
      broadcast = local->GetDefaultBroadcast();
    }
  } else {
    broadcast = IPAddress::CreateFromString(properties.broadcast_address,
                                            properties.address_family);
    if (!broadcast.has_value()) {
      LOG(ERROR) << "Broadcast address " << properties.broadcast_address
                 << " is invalid";
      return;
    }
  }

  bool is_p2p = false;
  if (!properties.peer_address.empty()) {
    const auto peer = IPAddress::CreateFromString(properties.peer_address,
                                                  properties.address_family);
    if (!peer.has_value()) {
      LOG(ERROR) << "Peer address " << properties.peer_address << " is invalid";
      return;
    }

    // For a PPP connection:
    // 1) Never set a peer (point-to-point) address, because the kernel
    //    will create an implicit routing rule in RT_TABLE_MAIN rather
    //    than our preferred routing table.  If the peer IP is set to the
    //    public IP of a VPN gateway (see below) this creates a routing loop.
    //    If not, it still creates an undesired route.
    // 2) Don't bother setting a gateway address either, because it doesn't
    //    have an effect on a point-to-point link.  So `ip route show table 1`
    //    will just say something like:
    //        default dev ppp0 metric 10
    is_p2p = true;
    // Reset |gateway| to default, so that the default route will be installed
    // by the code below.
    gateway = IPAddress::CreateFromFamily(properties.address_family);
  }

  // Skip address configuration if the address is from SLAAC. Note that IPv6 VPN
  // uses kTypeVPN as method, so kTypeIPv6 is always SLAAC.
  const bool skip_ip_configuration = properties.method == kTypeIPv6;
  if (!fixed_ip_params_ && !skip_ip_configuration) {
    if (const auto it = added_addresses_.find(local->family());
        it != added_addresses_.end() && it->second != local) {
      // The address has changed for this interface.  We need to flush
      // everything and start over.
      LOG(INFO) << __func__ << ": Flushing old addresses and routes.";
      // TODO(b/243336792): FlushRoutesWithTag() will not remove the IPv6 routes
      // managed by the kernel so this will not cause any problem now. Revisit
      // this part later.
      routing_table_->FlushRoutesWithTag(interface_index_);
      rtnl_handler_->RemoveInterfaceAddress(interface_index_, it->second);
    }

    LOG(INFO) << __func__ << ": Installing with parameters:"
              << " interface_name=" << interface_name_
              << " local=" << local->ToString() << " broadcast="
              << (broadcast.has_value() ? broadcast->ToString() : "<empty>")
              << " gateway="
              << (gateway.has_value() ? gateway->ToString() : "<empty>");

    rtnl_handler_->AddInterfaceAddress(
        interface_index_, *local,
        broadcast.has_value()
            ? *broadcast
            : IPAddress::CreateFromFamily_Deprecated(local->family()));
    added_addresses_.insert_or_assign(local->family(), *local);

    SetMTU(properties.mtu);
  }

  if (!SetupExcludedRoutes(properties)) {
    return;
  }

  if (!is_p2p && !FixGatewayReachability(*local, gateway)) {
    LOG(WARNING) << "Expect limited network connectivity.";
  }

  // For VPNs IPv6 overlay shill has to create default route by itself.
  // For physical networks with RAs it is done by kernel.
  if (gateway.has_value() && properties.default_route) {
    const bool is_ipv4 = gateway->family() == IPAddress::kFamilyIPv4;
    const bool is_vpn_ipv6 = properties.method == kTypeVPN &&
                             gateway->family() == IPAddress::kFamilyIPv6;
    if (is_ipv4 || is_vpn_ipv6) {
      routing_table_->SetDefaultRoute(interface_index_, *gateway, table_id_);
    }
  }

  if (properties.blackhole_ipv6) {
    routing_table_->CreateBlackholeRoute(interface_index_,
                                         IPAddress::kFamilyIPv6, 0, table_id_);
  }

  if (!SetupIncludedRoutes(properties, /*ignore_gateway=*/is_p2p)) {
    LOG(WARNING) << "Failed to set up additional routes";
  }

  UpdateRoutingPolicy();

  local_ = *local;
  if (gateway.has_value()) {
    gateway_ = *gateway;
  } else {
    gateway_ =
        IPAddress::CreateFromFamily_Deprecated(properties.address_family);
  }
}

void Connection::UpdateRoutingPolicy(
    const std::vector<IPAddress>& all_addresses) {
  addresses_for_routing_policy_ = all_addresses;
  UpdateRoutingPolicy();
}

void Connection::UpdateRoutingPolicy() {
  uint32_t rule_priority =
      kDefaultPriority + priority_.ranking_order * kPriorityStep;
  bool is_primary_physical = priority_.is_primary_physical;
  routing_table_->FlushRules(interface_index_);

  // b/180521518: IPv6 routing rules are always omitted for a Cellular
  // connection that is not the primary physical connection. This prevents
  // applications from accidentally using the Cellular network and causing data
  // charges with IPv6 traffic when the primary physical connection is IPv4
  // only.
  bool no_ipv6 = technology_ == Technology::kCellular && !is_primary_physical;

  // TODO(b/264963034): kUnknown here is to adapt to legacy test code where
  // kUnknown instead of kVPN is used as test case for non-physical interfaces.
  // Remove this and use kVPN in test code instead when executing the refactor.
  if (technology_ != Technology::kVPN && technology_ != Technology::kUnknown) {
    rule_priority += kPhysicalPriorityOffset;
  }

  AllowTrafficThrough(table_id_, rule_priority, no_ipv6);

  // b/177620923 Add uid rules just before the default rule to route to the VPN
  // interface any untagged traffic owner by a uid routed through VPN
  // connections. These rules are necessary for consistency between source IP
  // address selection algorithm that ignores iptables fwmark tagging rules, and
  // the actual routing of packets that have been tagged in iptables PREROUTING.
  if (technology_ == Technology::kVPN) {
    for (const auto& uid : routing_table_->GetUserTrafficUids()) {
      auto entry = RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                       .SetPriority(kVpnUidRulePriority)
                       .SetTable(table_id_)
                       .SetUid(uid);
      routing_table_->AddRule(interface_index_, entry);
      routing_table_->AddRule(interface_index_, entry.FlipFamily());
    }
  }

  if (is_primary_physical) {
    // Main routing table contains kernel-added routes for source address
    // selection. Sending traffic there before all other rules for physical
    // interfaces (but after any VPN rules) ensures that physical interface
    // rules are not inadvertently too aggressive. Since this rule is static,
    // add it as interface index -1 so it never get removed by FlushRules().
    // Note that this rule could be added multiple times when default network
    // changes, but since the rule itself is identical, there will only be one
    // instance added into kernel.
    auto main_table_rule = RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                               .SetPriority(kPhysicalPriorityOffset)
                               .SetTable(RT_TABLE_MAIN);
    routing_table_->AddRule(-1, main_table_rule);
    routing_table_->AddRule(-1, main_table_rule.FlipFamily());
    // Add a default routing rule to use the primary interface if there is
    // nothing better.
    // TODO(crbug.com/999589) Remove this rule.
    auto catch_all_rule = RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                              .SetTable(table_id_)
                              .SetPriority(kCatchallPriority);
    routing_table_->AddRule(interface_index_, catch_all_rule);
    routing_table_->AddRule(interface_index_, catch_all_rule.FlipFamily());
  }
}

void Connection::AllowTrafficThrough(uint32_t table_id,
                                     uint32_t base_priority,
                                     bool no_ipv6) {
  // b/189952150: when |no_ipv6| is true and shill must prevent IPv6 traffic on
  // this connection for applications, it is still necessary to ensure that some
  // critical system IPv6 traffic can be routed. Example: shill portal detection
  // probes when the network connection is IPv6 only. For the time being the
  // only supported case is traffic from shill.
  uint32_t shill_uid = getuid();

  for (const auto& dst_address : allowed_dsts_) {
    auto dst_addr_rule = RoutingPolicyEntry::CreateFromDst(dst_address)
                             .SetPriority(kDstRulePriority)
                             .SetTable(table_id);
    if (dst_address.family() == IPAddress::kFamilyIPv6 && no_ipv6) {
      dst_addr_rule.SetUid(shill_uid);
    }
    routing_table_->AddRule(interface_index_, dst_addr_rule);
  }

  // Always set a rule for matching traffic tagged with the fwmark routing tag
  // corresponding to this network interface.
  auto fwmark_routing_entry =
      RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
          .SetPriority(base_priority)
          .SetTable(table_id)
          .SetFwMark(GetFwmarkRoutingTag(interface_index_));
  routing_table_->AddRule(interface_index_, fwmark_routing_entry);
  if (no_ipv6) {
    fwmark_routing_entry.SetUid(shill_uid);
  }
  routing_table_->AddRule(interface_index_, fwmark_routing_entry.FlipFamily());

  // Add output interface rule for all interfaces, such that SO_BINDTODEVICE can
  // be used without explicitly binding the socket.
  auto oif_rule = RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                      .SetTable(table_id)
                      .SetPriority(base_priority)
                      .SetOif(interface_name_);
  routing_table_->AddRule(interface_index_, oif_rule);
  if (no_ipv6) {
    oif_rule.SetUid(shill_uid);
  }
  routing_table_->AddRule(interface_index_, oif_rule.FlipFamily());

  // TODO(b/264963034): kUnknown here is to adapt to legacy test code where
  // kUnknown instead of kVPN is used as test case for non-physical interfaces.
  // Remove this and use kVPN in test code instead when executing the refactor.
  if (technology_ != Technology::kVPN && technology_ != Technology::kUnknown) {
    // Select the per-device table if the outgoing packet's src address matches
    // the interface's addresses or the input interface is this interface.
    for (const auto& address : addresses_for_routing_policy_) {
      auto if_addr_rule = RoutingPolicyEntry::CreateFromSrc(address)
                              .SetTable(table_id)
                              .SetPriority(base_priority);
      if (address.family() == IPAddress::kFamilyIPv6 && no_ipv6) {
        if_addr_rule.SetUid(shill_uid);
      }
      routing_table_->AddRule(interface_index_, if_addr_rule);
    }
    auto iif_rule = RoutingPolicyEntry::Create(IPAddress::kFamilyIPv4)
                        .SetTable(table_id)
                        .SetPriority(base_priority)
                        .SetIif(interface_name_);
    routing_table_->AddRule(interface_index_, iif_rule);
    if (no_ipv6) {
      iif_rule.SetUid(shill_uid);
    }
    routing_table_->AddRule(interface_index_, iif_rule.FlipFamily());
  }
}

void Connection::SetPriority(NetworkPriority priority) {
  SLOG(this, 2) << __func__ << " " << interface_name_ << " (index "
                << interface_index_ << ")" << priority_ << " -> " << priority;
  if (priority == priority_) {
    return;
  }

  priority_ = priority;
  UpdateRoutingPolicy();
  routing_table_->FlushCache();
}

bool Connection::FixGatewayReachability(
    const IPAddress& local, const std::optional<IPAddress>& gateway) {
  if (!gateway.has_value()) {
    LOG(WARNING) << "No gateway address was provided for this connection.";
    return false;
  }

  SLOG(2) << __func__ << " local " << local.ToString() << ", gateway "
          << gateway->ToString();

  // The prefix check will usually fail on IPv6 because IPv6 gateways
  // typically use link-local addresses.
  if (local.CanReachAddress(*gateway) ||
      local.family() == IPAddress::kFamilyIPv6) {
    return true;
  }

  LOG(WARNING) << "Gateway " << gateway->ToString()
               << " is unreachable from local address/prefix "
               << local.ToString() << "/" << local.prefix();
  LOG(WARNING) << "Mitigating this by creating a link route to the gateway.";

  IPAddress gateway_with_max_prefix(*gateway);
  gateway_with_max_prefix.set_prefix(
      IPAddress::GetMaxPrefixLength(gateway_with_max_prefix.family()));
  const auto default_address =
      IPAddress::CreateFromFamily_Deprecated(gateway->family());
  auto entry = RoutingTableEntry::Create(gateway_with_max_prefix,
                                         default_address, default_address)
                   .SetScope(RT_SCOPE_LINK)
                   .SetTable(table_id_)
                   .SetType(RTN_UNICAST)
                   .SetTag(interface_index_);

  if (!routing_table_->AddRoute(interface_index_, entry)) {
    LOG(ERROR) << "Unable to add link-scoped route to gateway.";
    return false;
  }

  return true;
}

void Connection::SetMTU(int32_t mtu) {
  SLOG(this, 2) << __func__ << " " << mtu;
  // Make sure the MTU value is valid.
  if (mtu == IPConfig::kUndefinedMTU) {
    mtu = IPConfig::kDefaultMTU;
  } else {
    int min_mtu = IsIPv6() ? IPConfig::kMinIPv6MTU : IPConfig::kMinIPv4MTU;
    if (mtu < min_mtu) {
      SLOG(this, 2) << __func__ << " MTU " << mtu
                    << " is too small; adjusting up to " << min_mtu;
      mtu = min_mtu;
    }
  }

  rtnl_handler_->SetInterfaceMTU(interface_index_, mtu);
}

bool Connection::IsIPv6() {
  return local_.family() == IPAddress::kFamilyIPv6;
}

}  // namespace shill
