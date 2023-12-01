// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/network_applier.h"

#include <set>
#include <string>
#include <vector>

#include <base/memory/ptr_util.h>

#include "shill/ipconfig.h"
#include "shill/network/network_priority.h"

namespace shill {

NetworkApplier::NetworkApplier() : resolver_(Resolver::GetInstance()) {}

NetworkApplier::~NetworkApplier() = default;

// static
NetworkApplier* NetworkApplier::GetInstance() {
  static base::NoDestructor<NetworkApplier> instance;
  return instance.get();
}

// static
std::unique_ptr<NetworkApplier> NetworkApplier::CreateForTesting(
    Resolver* resolver) {
  // Using `new` to access a non-public constructor.
  auto ptr = base::WrapUnique(new NetworkApplier());
  ptr->resolver_ = resolver;
  return ptr;
}

void NetworkApplier::ApplyDNS(NetworkPriority priority,
                              const IPConfig::Properties* ipv4_properties,
                              const IPConfig::Properties* ipv6_properties) {
  if (!priority.is_primary_for_dns) {
    return;
  }
  std::vector<std::string> dns_servers;
  std::vector<std::string> domain_search;
  std::set<std::string> domain_search_dedup;
  // When DNS information is available from both IPv6 source (RDNSS) and IPv4
  // source (DHCPv4), the ideal behavior is happy eyeballs (RFC 8305). When
  // happy eyeballs is not implemented, the priority of DNS servers are not
  // strictly defined by standard. Prefer IPv6 here as most of the RFCs just
  // "assume" IPv6 is preferred.
  for (const auto* properties : {ipv6_properties, ipv4_properties}) {
    if (!properties) {
      continue;
    }
    dns_servers.insert(dns_servers.end(), properties->dns_servers.begin(),
                       properties->dns_servers.end());

    for (const auto& item : properties->domain_search) {
      if (domain_search_dedup.count(item) == 0) {
        domain_search.push_back(item);
        domain_search_dedup.insert(item);
      }
    }
    if (properties->domain_search.empty() && !properties->domain_name.empty()) {
      auto search_list_derived = properties->domain_name + ".";
      if (domain_search_dedup.count(search_list_derived) == 0) {
        domain_search.push_back(search_list_derived);
        domain_search_dedup.insert(search_list_derived);
      }
    }
  }
  resolver_->SetDNSFromLists(dns_servers, domain_search);
}
}  // namespace shill
