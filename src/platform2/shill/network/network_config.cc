// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/network_config.h"

#include <base/strings/string_util.h>

namespace shill {

NetworkConfig::NetworkConfig() = default;
NetworkConfig::~NetworkConfig() = default;

std::ostream& operator<<(std::ostream& stream, const NetworkConfig& config) {
  stream << "{IPv4 address: "
         << (config.ipv4_address_cidr.has_value() ? *config.ipv4_address_cidr
                                                  : "nullopt");
  if (config.ipv4_route.gateway) {
    stream << ", IPv4 gateway: " << *config.ipv4_route.gateway;
  }
  if (config.ipv4_route.included_route_prefixes) {
    stream << ", IPv4 included routes: ["
           << base::JoinString(*config.ipv4_route.included_route_prefixes, ",")
           << "]";
  }
  if (config.ipv4_route.excluded_route_prefixes) {
    stream << ", IPv4 excluded routes: ["
           << base::JoinString(*config.ipv4_route.excluded_route_prefixes, ",")
           << "]";
  }
  stream << ", IPv6 addresses: [";
  if (config.ipv6_address_cidrs) {
    stream << base::JoinString(*config.ipv6_address_cidrs, ",");
  }
  stream << "]";
  if (config.ipv6_route.gateway) {
    stream << ", IPv6 gateway: " << *config.ipv6_route.gateway;
  }
  if (config.ipv6_route.included_route_prefixes) {
    stream << ", IPv6 included routes: ["
           << base::JoinString(*config.ipv6_route.included_route_prefixes, ",")
           << "]";
  }
  if (config.ipv6_route.excluded_route_prefixes) {
    stream << ", IPv6 excluded routes: ["
           << base::JoinString(*config.ipv6_route.excluded_route_prefixes, ",")
           << "]";
  }
  if (config.dns_servers) {
    stream << ", DNS: [" << base::JoinString(*config.dns_servers, ",") << "]";
  }
  if (config.dns_search_domains) {
    stream << ", search domains: ["
           << base::JoinString(*config.dns_search_domains, ",") << "]";
  }
  if (config.mtu) {
    stream << ", mtu: " << *config.mtu;
  }
  return stream << "}";
}

}  // namespace shill
