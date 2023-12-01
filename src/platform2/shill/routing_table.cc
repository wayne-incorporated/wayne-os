// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/routing_table.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>  // NOLINT - must be included after netinet/ether.h
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <limits>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/userdb_utils.h>

#include "shill/logging.h"
#include "shill/net/byte_string.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_listener.h"
#include "shill/net/rtnl_message.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kRoute;
}  // namespace Logging

namespace {

base::LazyInstance<RoutingTable>::DestructorAtExit g_routing_table =
    LAZY_INSTANCE_INITIALIZER;

const char kIpv6ProcPath[] = "/proc/sys/net/ipv6/conf";
const char kIpv4RouteFlushPath[] = "/proc/sys/net/ipv4/route/flush";
const char kIpv6RouteFlushPath[] = "/proc/sys/net/ipv6/route/flush";
// Amount added to an interface index to come up with the routing table ID for
// that interface.
constexpr int kInterfaceTableIdIncrement = 1000;
static_assert(
    kInterfaceTableIdIncrement > RT_TABLE_LOCAL,
    "kInterfaceTableIdIncrement must be greater than RT_TABLE_LOCAL, "
    "as otherwise some interface's table IDs may collide with system tables.");

// For VPN drivers that only want to pass traffic for specific users,
// these are the usernames that will be used to create the routing policy
// rules. Also, when an AlwaysOnVpnPackage is set and a corresponding VPN
// service is not active, traffic from these users will blackholed.
// Currently the "user traffic" as defined by these usernames does not include
// e.g. Android apps or system processes like the update engine.
constexpr std::array<const char*, 9> kUserTrafficUsernames = {
    "chronos",         // Traffic originating from chrome and nacl applications
    "debugd",          // crosh terminal
    "cups",            // built-in printing using the cups daemon
    "lpadmin",         // printer configuration utility used by cups
    "kerberosd",       // Chrome OS Kerberos daemon
    "kerberosd-exec",  // Kerberos third party untrusted code
    // While tlsdate is not user traffic, time sync should be attempted over
    // VPN. It is OK to send tlsdate traffic over VPN because it will also try
    // to sync time immediately after boot on the sign-in screen when no VPN can
    // be active.
    // TODO(https://crbug.com/1065378): Find a way for tlsdate to try both with
    // and without VPN explicitly.
    "tlsdate",    // tlsdate daemon (secure time sync)
    "pluginvm",   // plugin vm problem report utility (b/160916677)
    "fuse-smbfs"  // smbfs SMB filesystem daemon
};

bool ParseRoutingTableMessage(const RTNLMessage& message,
                              int* interface_index,
                              RoutingTableEntry* entry) {
  if (message.type() != RTNLMessage::kTypeRoute ||
      message.family() == IPAddress::kFamilyUnknown ||
      !message.HasAttribute(RTA_OIF)) {
    return false;
  }

  const RTNLMessage::RouteStatus& route_status = message.route_status();

  if (route_status.type != RTN_UNICAST) {
    return false;
  }

  if (route_status.table == RT_TABLE_LOCAL) {
    // Shill does not modify local routes, which are managed by the kernel.
    return false;
  }

  uint32_t interface_index_u32 = 0;
  if (!message.GetAttribute(RTA_OIF).ConvertToCPUUInt32(&interface_index_u32)) {
    return false;
  }
  *interface_index = interface_index_u32;

  uint32_t metric = 0;
  if (message.HasAttribute(RTA_PRIORITY)) {
    message.GetAttribute(RTA_PRIORITY).ConvertToCPUUInt32(&metric);
  }

  // The rtmsg structure [0] has a table id field that is only a single
  // byte. Prior to Linux v2.6, routing table IDs were of type u8. v2.6 changed
  // this so that table IDs were u32s, but the uapi here couldn't
  // change. Instead, a separate RTA_TABLE attribute is used to be able to send
  // a full 32-bit table ID. When the table ID is greater than 255, the
  // rtm_table field is set to RT_TABLE_COMPAT.
  //
  // 0) elixir.bootlin.com/linux/v5.0/source/include/uapi/linux/rtnetlink.h#L206
  uint32_t table;
  if (message.HasAttribute(RTA_TABLE)) {
    message.GetAttribute(RTA_TABLE).ConvertToCPUUInt32(&table);
  } else {
    table = route_status.table;
    LOG_IF(WARNING, table == RT_TABLE_COMPAT)
        << "Received RT_TABLE_COMPAT, but message has no RTA_TABLE attribute";
  }

  const auto default_addr = IPAddress::CreateFromFamily(message.family());
  if (auto addr = message.GetRtaDst(); addr.has_value()) {
    entry->dst = std::move(*addr);
  } else {
    entry->dst = default_addr;
  }
  if (auto addr = message.GetRtaSrc(); addr.has_value()) {
    entry->src = std::move(*addr);
  } else {
    entry->src = default_addr;
  }
  if (auto addr = message.GetRtaGateway(); addr.has_value()) {
    entry->gateway = std::move(*addr);
  } else {
    entry->gateway = default_addr;
  }
  entry->table = table;
  entry->metric = metric;
  entry->scope = route_status.scope;
  entry->protocol = route_status.protocol;
  entry->type = route_status.type;

  return true;
}

std::vector<uint32_t> ComputeUserTrafficUids() {
  std::vector<uint32_t> uids;
  for (const auto& username : kUserTrafficUsernames) {
    uid_t uid;
    if (!brillo::userdb::GetUserInfo(username, &uid, nullptr)) {
      LOG(WARNING) << "Unable to look up UID for " << username;
      continue;
    }
    uids.push_back(uint32_t{uid});
  }
  return uids;
}

}  // namespace

// These don't have named constants in the system header files, but they
// are documented in ip-rule(8) and hardcoded in net/ipv4/fib_rules.c.

RoutingTable::RoutingTable() : rtnl_handler_(RTNLHandler::GetInstance()) {
  SLOG(2) << __func__;
}

RoutingTable::~RoutingTable() = default;

RoutingTable* RoutingTable::GetInstance() {
  return g_routing_table.Pointer();
}

void RoutingTable::Start() {
  SLOG(2) << __func__;

  route_listener_.reset(
      new RTNLListener(RTNLHandler::kRequestRoute | RTNLHandler::kRequestRule,
                       base::BindRepeating(&RoutingTable::RouteMsgHandler,
                                           base::Unretained(this))));
  rtnl_handler_->RequestDump(RTNLHandler::kRequestRoute);
  rtnl_handler_->RequestDump(RTNLHandler::kRequestRule);
}

void RoutingTable::Stop() {
  SLOG(2) << __func__;

  managed_interfaces_.clear();
  route_listener_.reset();
}

void RoutingTable::RegisterDevice(int interface_index,
                                  const std::string& link_name) {
  if (managed_interfaces_.find(interface_index) != managed_interfaces_.end()) {
    return;
  }

  LOG(INFO) << "Device " << link_name << " registered.";
  managed_interfaces_.insert(interface_index);

  uint32_t table_id = GetInterfaceTableId(interface_index);
  // Move existing entries for this interface to the per-Device table.
  for (auto& nent : tables_[interface_index]) {
    if (nent.table == table_id) {
      continue;
    }
    RoutingTableEntry new_entry = nent;
    new_entry.table = table_id;
    AddRouteToKernelTable(interface_index, new_entry);
    RemoveRouteFromKernelTable(interface_index, nent);
    nent.table = table_id;
  }

  // Set accept_ra_rt_table to -N to cause routes created by the reception of
  // RAs to be sent to the table id (interface_index + N).
  std::string ra_rt_table = std::to_string(-kInterfaceTableIdIncrement);
  auto path = base::FilePath(kIpv6ProcPath)
                  .Append(link_name)
                  .Append("accept_ra_rt_table");
  int str_size = static_cast<int>(ra_rt_table.size());
  if (base::WriteFile(path, ra_rt_table.c_str(), str_size) != str_size) {
    LOG(ERROR) << "Cannot write to " << path.MaybeAsASCII();
  }
  FlushCache();
}

void RoutingTable::DeregisterDevice(int interface_index,
                                    const std::string& link_name) {
  LOG(INFO) << "Device " << link_name << " deregistered.";
  managed_interfaces_.erase(interface_index);
  // Set accept_ra_rt_table to 0. Note that this will *not* cause routes to be
  // moved back from the per-Device table to the main routing table.
  auto path = base::FilePath(kIpv6ProcPath)
                  .Append(link_name)
                  .Append("accept_ra_rt_table");
  if (!base::PathExists(path)) {
    SLOG(2) << "Cannot write to " << path.MaybeAsASCII()
            << ", likely because the interface has already went down.";
  } else if (base::WriteFile(path, "0", 1) != 1) {
    // Note that there is a potential race condition in which the file exists in
    // the check above but is removed by the time we call WriteFile. In this
    // case, the following error log will be spurious.
    LOG(ERROR) << "Cannot write to " << path.MaybeAsASCII();
  }
  FlushCache();
}

bool RoutingTable::AddRoute(int interface_index,
                            const RoutingTableEntry& entry) {
  // Normal routes (i.e. not blackhole or unreachable) should be sent to a
  // the interface's per-device table.
  if (entry.table != GetInterfaceTableId(interface_index) &&
      entry.type != RTN_BLACKHOLE && entry.type != RTN_UNREACHABLE) {
    LOG(ERROR) << "Can't add route to table " << entry.table
               << " when the interface's per-device table is "
               << GetInterfaceTableId(interface_index);
    return false;
  }

  if (!AddRouteToKernelTable(interface_index, entry)) {
    return false;
  }
  tables_[interface_index].push_back(entry);
  return true;
}

bool RoutingTable::RemoveRoute(int interface_index,
                               const RoutingTableEntry& entry) {
  if (!RemoveRouteFromKernelTable(interface_index, entry)) {
    return false;
  }
  RouteTableEntryVector& table = tables_[interface_index];
  for (auto nent = table.begin(); nent != table.end(); ++nent) {
    if (*nent == entry) {
      table.erase(nent);
      return true;
    }
  }
  SLOG(1) << "Successfully removed routing entry but could not find the "
          << "corresponding entry in shill's representation of the "
          << "routing table.";
  return true;
}

bool RoutingTable::GetDefaultRoute(int interface_index,
                                   IPAddress::Family family,
                                   RoutingTableEntry* entry) {
  RoutingTableEntry* found_entry;
  bool ret = GetDefaultRouteInternal(interface_index, family, &found_entry);
  if (ret) {
    *entry = *found_entry;
  }
  return ret;
}

bool RoutingTable::GetDefaultRouteInternal(int interface_index,
                                           IPAddress::Family family,
                                           RoutingTableEntry** entry) {
  SLOG(2) << __func__ << " index " << interface_index << " family "
          << IPAddress::GetAddressFamilyName(family);

  RouteTables::iterator table = tables_.find(interface_index);
  if (table == tables_.end()) {
    SLOG(2) << __func__ << " no table";
    return false;
  }

  // For IPv6 the kernel will add a new default route with metric 1024
  // every time it sees a router advertisement (which could happen every
  // couple of seconds).  Ignore these when there is another default route
  // with a lower metric.
  uint32_t lowest_metric = UINT_MAX;
  for (auto& nent : table->second) {
    if (nent.dst.IsDefault() && nent.dst.family() == family &&
        nent.metric < lowest_metric) {
      *entry = &nent;
      lowest_metric = nent.metric;
    }
  }

  if (lowest_metric == UINT_MAX) {
    SLOG(2) << __func__ << " no route";
    return false;
  } else {
    SLOG(2) << __func__ << ": found"
            << " gateway " << (*entry)->gateway.ToString() << " metric "
            << (*entry)->metric;
    return true;
  }
}

bool RoutingTable::GetDefaultRouteFromKernel(int interface_index,
                                             RoutingTableEntry* entry) {
  SLOG(2) << __func__ << " index " << interface_index;

  RouteTables::iterator table = tables_.find(interface_index);
  if (table == tables_.end()) {
    SLOG(2) << __func__ << " no table";
    return false;
  }

  for (auto& nent : table->second) {
    if (nent.dst.IsDefault() && nent.dst.family() == IPAddress::kFamilyIPv6 &&
        nent.metric == kKernelSlaacRouteMetric) {
      *entry = nent;
      return true;
    }
  }
  return false;
}

bool RoutingTable::SetDefaultRoute(int interface_index,
                                   const IPAddress& gateway_address,
                                   uint32_t table_id) {
  SLOG(2) << __func__ << " index " << interface_index;

  RoutingTableEntry* old_entry;

  if (GetDefaultRouteInternal(interface_index, gateway_address.family(),
                              &old_entry)) {
    if (old_entry->gateway.Equals(gateway_address) &&
        old_entry->table == table_id) {
      return true;
    } else {
      if (!RemoveRoute(interface_index, *old_entry)) {
        LOG(WARNING) << "Failed to remove old default route for interface "
                     << interface_index;
      }
    }
  }

  const auto default_address =
      IPAddress::CreateFromFamily(gateway_address.family());

  return AddRoute(interface_index,
                  RoutingTableEntry::Create(default_address, default_address,
                                            gateway_address)
                      .SetMetric(kShillDefaultRouteMetric)
                      .SetTable(table_id)
                      .SetTag(interface_index));
}

void RoutingTable::FlushRoutes(int interface_index) {
  SLOG(2) << __func__;

  auto table = tables_.find(interface_index);
  if (table == tables_.end()) {
    return;
  }

  for (const auto& nent : table->second) {
    RemoveRouteFromKernelTable(interface_index, nent);
  }
  table->second.clear();
}

void RoutingTable::FlushRoutesWithTag(int tag) {
  SLOG(2) << __func__;

  for (auto& table : tables_) {
    for (auto nent = table.second.begin(); nent != table.second.end();) {
      if (nent->tag == tag) {
        RemoveRouteFromKernelTable(table.first, *nent);
        nent = table.second.erase(nent);
      } else {
        ++nent;
      }
    }
  }
}

void RoutingTable::ResetTable(int interface_index) {
  tables_.erase(interface_index);
}

bool RoutingTable::AddRouteToKernelTable(int interface_index,
                                         const RoutingTableEntry& entry) {
  SLOG(2) << __func__ << ": "
          << " index " << interface_index << " " << entry;

  return ApplyRoute(interface_index, entry, RTNLMessage::kModeAdd,
                    NLM_F_CREATE | NLM_F_EXCL);
}

bool RoutingTable::RemoveRouteFromKernelTable(int interface_index,
                                              const RoutingTableEntry& entry) {
  SLOG(2) << __func__ << ": "
          << " index " << interface_index << " " << entry;

  return ApplyRoute(interface_index, entry, RTNLMessage::kModeDelete, 0);
}

void RoutingTable::RouteMsgHandler(const RTNLMessage& message) {
  if (HandleRoutingPolicyMessage(message)) {
    return;
  }

  int interface_index;
  // Initialize it to IPv4, will be set to the real value in
  // ParseRoutingTableMessage().
  RoutingTableEntry entry(IPAddress::kFamilyIPv4);
  if (!ParseRoutingTableMessage(message, &interface_index, &entry)) {
    return;
  }

  if (!route_queries_.empty() && entry.protocol == RTPROT_UNSPEC) {
    SLOG(3) << __func__ << ": Message seq: " << message.seq() << " mode "
            << message.mode()
            << ", next query seq: " << route_queries_.front().sequence;

    // Purge queries that have expired (sequence number of this message is
    // greater than that of the head of the route query sequence).  Do the
    // math in a way that's roll-over independent.
    const auto kuint32max = std::numeric_limits<uint32_t>::max();
    while (route_queries_.front().sequence - message.seq() > kuint32max / 2) {
      LOG(ERROR) << __func__ << ": Purging un-replied route request sequence "
                 << route_queries_.front().sequence << " (< " << message.seq()
                 << ")";
      route_queries_.pop_front();
      if (route_queries_.empty())
        return;
    }

    Query& query = route_queries_.front();
    if (query.sequence == message.seq()) {
      if (!query.callback.is_null()) {
        SLOG(2) << "Running query callback.";
        std::move(query.callback).Run(interface_index, entry);
      }
      route_queries_.pop_front();
    }
    return;
  } else if (entry.protocol == RTPROT_RA) {
    // The kernel sends one of these messages pretty much every time it
    // connects to another IPv6 host.  The only interesting message is the
    // one containing the default gateway.
    if (!entry.dst.IsDefault())
      return;
  } else if (entry.protocol != RTPROT_BOOT) {
    // Responses to route queries come back with a protocol of
    // RTPROT_UNSPEC.  Otherwise, normal route updates that we are
    // interested in come with a protocol of RTPROT_BOOT.
    return;
  }

  SLOG(2) << __func__ << " " << RTNLMessage::ModeToString(message.mode())
          << " index: " << interface_index << " entry: " << entry;

  bool entry_exists = false;
  bool is_managed = (managed_interfaces_.count(interface_index) != 0);
  uint32_t target_table = GetInterfaceTableId(interface_index);
  // Routes that make it here are either:
  //   * Default routes of protocol RTPROT_RA (most notably, kernel-created IPv6
  //      default routes in response to receiving IPv6 RAs).
  //   * Routes of protocol RTPROT_BOOT, which includes default routes created
  //      by the kernel when an interface comes up and routes created by `ip
  //      route` that do not explicitly specify a different protocol.
  //
  // Thus a different service could create routes that are "hidden" from Shill
  // by using a different protocol value (anything greater than RTPROT_STATIC
  // would be appropriate), while routes created with protocol RTPROT_BOOT will
  // be tracked by Shill. In the future, each service could use a unique
  // protocol value, such that Shill would be able to determine which service
  // created a particular route.
  RouteTableEntryVector& table = tables_[interface_index];
  for (auto nent = table.begin(); nent != table.end();) {
    // clang-format off
    if (nent->dst != entry.dst ||
        nent->src != entry.src ||
        nent->gateway != entry.gateway ||
        nent->scope != entry.scope ||
        nent->metric != entry.metric ||
        nent->type != entry.type) {
      ++nent;
      continue;
    }
    // clang-format on

    if (message.mode() == RTNLMessage::kModeAdd &&
        (is_managed || entry.table == nent->table)) {
      // Set this to true to avoid adding the same route twice to
      // tables_[interface_index].
      entry_exists = true;
      break;
    }

    if (message.mode() == RTNLMessage::kModeDelete &&
        entry.table == nent->table) {
      // Keep track of route deletions that come from outside of shill. Continue
      // the loop for resilience to any failure scenario in which
      // tables_[interface_index] has duplicate entries.
      nent = table.erase(nent);
    } else {
      ++nent;
    }
  }

  if (message.mode() != RTNLMessage::kModeAdd) {
    return;
  }

  // We do not want normal entries for a managed interface to be added to any
  // table but the per-Device routing table. Thus we remove the added route here
  // and re-add it to the per-Device routing table.
  if (is_managed && entry.table != target_table && entry.type == RTN_UNICAST) {
    RoutingTableEntry oldEntry(entry);
    entry.table = target_table;
    ApplyRoute(interface_index, entry, RTNLMessage::kModeAdd,
               NLM_F_CREATE | NLM_F_REPLACE);
    RemoveRouteFromKernelTable(interface_index, oldEntry);
  }

  if (!entry_exists) {
    table.push_back(entry);
  }
}

bool RoutingTable::ApplyRoute(uint32_t interface_index,
                              const RoutingTableEntry& entry,
                              RTNLMessage::Mode mode,
                              unsigned int flags) {
  DCHECK(entry.table != RT_TABLE_UNSPEC && entry.table != RT_TABLE_COMPAT)
      << "Attempted to apply route: " << entry;

  SLOG(2) << base::StringPrintf(
      "%s: dst %s/%d src %s/%d index %d mode %d flags 0x%x", __func__,
      entry.dst.ToString().c_str(), entry.dst.prefix(),
      entry.src.ToString().c_str(), entry.src.prefix(), interface_index, mode,
      flags);

  auto message = std::make_unique<RTNLMessage>(RTNLMessage::kTypeRoute, mode,
                                               NLM_F_REQUEST | flags, 0, 0, 0,
                                               entry.dst.family());
  message->set_route_status(RTNLMessage::RouteStatus(
      entry.dst.prefix(), entry.src.prefix(),
      entry.table < 256 ? entry.table : RT_TABLE_COMPAT, entry.protocol,
      entry.scope, entry.type, 0));

  message->SetAttribute(RTA_TABLE,
                        ByteString::CreateFromCPUUInt32(entry.table));
  message->SetAttribute(RTA_PRIORITY,
                        ByteString::CreateFromCPUUInt32(entry.metric));
  if (entry.type != RTN_BLACKHOLE) {
    message->SetAttribute(RTA_DST, entry.dst.address());
  }
  if (!entry.src.IsDefault()) {
    message->SetAttribute(RTA_SRC, entry.src.address());
  }
  if (!entry.gateway.IsDefault()) {
    message->SetAttribute(RTA_GATEWAY, entry.gateway.address());
  }
  if (entry.type == RTN_UNICAST) {
    // Note that RouteMsgHandler will ignore anything without RTA_OIF,
    // because that is how it looks up the |tables_| vector.  But
    // FlushRoutes() and FlushRoutesWithTag() do not care.
    message->SetAttribute(RTA_OIF,
                          ByteString::CreateFromCPUUInt32(interface_index));
  }

  return rtnl_handler_->SendMessage(std::move(message), nullptr);
}

bool RoutingTable::FlushCache() {
  static const char* const kPaths[] = {kIpv4RouteFlushPath,
                                       kIpv6RouteFlushPath};
  bool ret = true;

  SLOG(2) << __func__;

  for (auto path : kPaths) {
    if (base::WriteFile(base::FilePath(path), "-1", 2) != 2) {
      LOG(ERROR) << base::StringPrintf("Cannot write to route flush file %s",
                                       path);
      ret = false;
    }
  }

  return ret;
}

bool RoutingTable::RequestRouteToHost(const IPAddress& address,
                                      int interface_index,
                                      QueryCallback callback) {
  // Make sure we don't get a cached response that is no longer valid.
  FlushCache();

  auto message = std::make_unique<RTNLMessage>(
      RTNLMessage::kTypeRoute, RTNLMessage::kModeQuery, NLM_F_REQUEST, 0, 0,
      interface_index, address.family());
  RTNLMessage::RouteStatus status;
  status.dst_prefix = address.prefix();
  message->set_route_status(status);
  message->SetAttribute(RTA_DST, address.address());

  if (interface_index != -1) {
    message->SetAttribute(RTA_OIF,
                          ByteString::CreateFromCPUUInt32(interface_index));
  }

  uint32_t seq;
  if (!rtnl_handler_->SendMessage(std::move(message), &seq)) {
    return false;
  }

  // Save the sequence number of the request so we can trigger the callback
  // when we get a reply.
  route_queries_.push_back(Query(seq, std::move(callback)));

  return true;
}

bool RoutingTable::CreateBlackholeRoute(int interface_index,
                                        IPAddress::Family family,
                                        uint32_t metric,
                                        uint32_t table_id) {
  SLOG(2) << base::StringPrintf("%s: family %s metric %d", __func__,
                                IPAddress::GetAddressFamilyName(family).c_str(),
                                metric);

  auto entry = RoutingTableEntry::Create(family)
                   .SetMetric(metric)
                   .SetTable(table_id)
                   .SetType(RTN_BLACKHOLE)
                   .SetTag(interface_index);
  return AddRoute(interface_index, entry);
}

bool RoutingTable::CreateLinkRoute(int interface_index,
                                   const IPAddress& local_address,
                                   const IPAddress& remote_address,
                                   uint32_t table_id) {
  if (!local_address.CanReachAddress(remote_address)) {
    LOG(ERROR) << __func__ << " failed: " << remote_address.ToString()
               << " is not reachable from " << local_address.ToString();
    return false;
  }

  IPAddress default_address =
      IPAddress::CreateFromFamily(local_address.family());
  IPAddress destination_address(remote_address);
  destination_address.set_prefix(
      IPAddress::GetMaxPrefixLength(remote_address.family()));
  SLOG(2) << "Creating link route to " << destination_address.ToString()
          << " from " << local_address.ToString() << " on interface index "
          << interface_index;
  return AddRoute(interface_index,
                  RoutingTableEntry::Create(destination_address, local_address,
                                            default_address)
                      .SetScope(RT_SCOPE_LINK)
                      .SetTable(table_id));
}

bool RoutingTable::ApplyRule(uint32_t interface_index,
                             const RoutingPolicyEntry& entry,
                             RTNLMessage::Mode mode,
                             unsigned int flags) {
  SLOG(2) << base::StringPrintf(
      "%s: index %d family %s prio %d", __func__, interface_index,
      IPAddress::GetAddressFamilyName(entry.family).c_str(), entry.priority);

  auto message = std::make_unique<RTNLMessage>(RTNLMessage::kTypeRule, mode,
                                               NLM_F_REQUEST | flags, 0, 0, 0,
                                               entry.family);
  message->set_route_status(RTNLMessage::RouteStatus(
      entry.dst.prefix(), entry.src.prefix(),
      entry.table < 256 ? entry.table : RT_TABLE_COMPAT, RTPROT_BOOT,
      RT_SCOPE_UNIVERSE, RTN_UNICAST, entry.invert_rule ? FIB_RULE_INVERT : 0));

  message->SetAttribute(FRA_TABLE,
                        ByteString::CreateFromCPUUInt32(entry.table));
  message->SetAttribute(FRA_PRIORITY,
                        ByteString::CreateFromCPUUInt32(entry.priority));
  if (entry.fw_mark.has_value()) {
    const RoutingPolicyEntry::FwMark& mark = entry.fw_mark.value();
    message->SetAttribute(FRA_FWMARK,
                          ByteString::CreateFromCPUUInt32(mark.value));
    message->SetAttribute(FRA_FWMASK,
                          ByteString::CreateFromCPUUInt32(mark.mask));
  }
  if (entry.uid_range.has_value()) {
    message->SetAttribute(FRA_UID_RANGE,
                          ByteString(reinterpret_cast<const unsigned char*>(
                                         &entry.uid_range.value()),
                                     sizeof(entry.uid_range.value())));
  }
  if (entry.iif_name.has_value()) {
    message->SetAttribute(FRA_IFNAME, ByteString(entry.iif_name.value(), true));
  }
  if (entry.oif_name.has_value()) {
    message->SetAttribute(FRA_OIFNAME,
                          ByteString(entry.oif_name.value(), true));
  }
  if (!entry.dst.IsDefault()) {
    message->SetAttribute(FRA_DST, entry.dst.address());
  }
  if (!entry.src.IsDefault()) {
    message->SetAttribute(FRA_SRC, entry.src.address());
  }

  return rtnl_handler_->SendMessage(std::move(message), nullptr);
}

bool RoutingTable::ParseRoutingPolicyMessage(const RTNLMessage& message,
                                             RoutingPolicyEntry* entry) {
  if (message.type() != RTNLMessage::kTypeRule ||
      message.family() == IPAddress::kFamilyUnknown) {
    return false;
  }

  const RTNLMessage::RouteStatus& route_status = message.route_status();
  if (route_status.type != RTN_UNICAST) {
    return false;
  }

  entry->family = message.family();
  entry->src = IPAddress::CreateFromFamily(entry->family);
  entry->dst = IPAddress::CreateFromFamily(entry->family);

  entry->invert_rule = !!(route_status.flags & FIB_RULE_INVERT);

  // The rtmsg structure [0] has a table id field that is only a single
  // byte. Prior to Linux v2.6, routing table IDs were of type u8. v2.6 changed
  // this so that table IDs were u32s, but the uapi here couldn't
  // change. Instead, a separate FRA_TABLE attribute is used to be able to send
  // a full 32-bit table ID. When the table ID is greater than 255, the
  // rtm_table field is set to RT_TABLE_COMPAT.
  //
  // 0) elixir.bootlin.com/linux/v5.0/source/include/uapi/linux/rtnetlink.h#L206
  uint32_t table;
  if (message.HasAttribute(FRA_TABLE)) {
    message.GetAttribute(FRA_TABLE).ConvertToCPUUInt32(&table);
  } else {
    table = route_status.table;
    LOG_IF(WARNING, table == RT_TABLE_COMPAT)
        << "Received RT_TABLE_COMPAT, but message has no FRA_TABLE attribute";
  }
  entry->SetTable(table);

  if (message.HasAttribute(FRA_PRIORITY)) {
    // Rule 0 (local table) doesn't have a priority attribute.
    if (!message.GetAttribute(FRA_PRIORITY)
             .ConvertToCPUUInt32(&entry->priority)) {
      return false;
    }
  }

  if (message.HasAttribute(FRA_FWMARK)) {
    RoutingPolicyEntry::FwMark fw_mark;
    if (!message.GetAttribute(FRA_FWMARK).ConvertToCPUUInt32(&fw_mark.value)) {
      return false;
    }
    if (message.HasAttribute(FRA_FWMASK)) {
      if (!message.GetAttribute(FRA_FWMASK).ConvertToCPUUInt32(&fw_mark.mask)) {
        return false;
      }
    }
    entry->SetFwMark(fw_mark);
  }

  if (message.HasAttribute(FRA_UID_RANGE)) {
    struct fib_rule_uid_range r;
    if (!message.GetAttribute(FRA_UID_RANGE).CopyData(sizeof(r), &r)) {
      return false;
    }
    entry->SetUidRange(r);
  }

  if (message.HasAttribute(FRA_IFNAME)) {
    entry->SetIif(reinterpret_cast<const char*>(
        message.GetAttribute(FRA_IFNAME).GetConstData()));
  }
  if (message.HasAttribute(FRA_OIFNAME)) {
    entry->SetOif(reinterpret_cast<const char*>(
        message.GetAttribute(FRA_OIFNAME).GetConstData()));
  }

  if (auto tmp_dst = message.GetFraDst(); tmp_dst.has_value()) {
    entry->dst = std::move(*tmp_dst);
  }
  if (auto tmp_src = message.GetFraSrc(); tmp_src.has_value()) {
    entry->src = std::move(*tmp_src);
  }

  return true;
}

bool RoutingTable::HandleRoutingPolicyMessage(const RTNLMessage& message) {
  // Family will be set to the real value in ParseRoutingPolicyMessage().
  RoutingPolicyEntry entry(IPAddress::kFamilyIPv4);

  if (!ParseRoutingPolicyMessage(message, &entry)) {
    return false;
  }

  if (!(entry.priority > kRulePriorityLocal &&
        entry.priority < kRulePriorityMain)) {
    // Don't touch the system-managed rules.
    return true;
  }

  // If this rule matches one of our known rules, ignore it.  Otherwise,
  // assume it is left over from an old run and delete it.
  for (auto& table : policy_tables_) {
    for (auto nent = table.second.begin(); nent != table.second.end(); ++nent) {
      if (*nent == entry) {
        return true;
      }
    }
  }

  ApplyRule(-1, entry, RTNLMessage::kModeDelete, 0);
  return true;
}

bool RoutingTable::AddRule(int interface_index,
                           const RoutingPolicyEntry& entry) {
  if (!ApplyRule(interface_index, entry, RTNLMessage::kModeAdd,
                 NLM_F_CREATE | NLM_F_EXCL)) {
    return false;
  }
  // Add entry into policy table if no identical entry exists.
  // Note that the main routing table route can be added multiple times without
  // removal so duplication check is essential here.
  auto& policy_table = policy_tables_[interface_index];
  if (std::find(policy_table.begin(), policy_table.end(), entry) !=
      policy_table.end()) {
    return true;
  }
  policy_table.push_back(entry);
  return true;
}

void RoutingTable::FlushRules(int interface_index) {
  SLOG(2) << __func__;

  auto table = policy_tables_.find(interface_index);
  if (table == policy_tables_.end()) {
    return;
  }

  for (const auto& nent : table->second) {
    ApplyRule(interface_index, nent, RTNLMessage::kModeDelete, 0);
  }
  table->second.clear();
}

// static
uint32_t RoutingTable::GetInterfaceTableId(int interface_index) {
  return static_cast<uint32_t>(interface_index + kInterfaceTableIdIncrement);
}

const std::vector<uint32_t>& RoutingTable::GetUserTrafficUids() {
  if (user_traffic_uids_.empty()) {
    user_traffic_uids_ = ComputeUserTrafficUids();
  }
  return user_traffic_uids_;
}

}  // namespace shill
