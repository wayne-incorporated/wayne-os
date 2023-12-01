// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_NETWORK_CONFIG_H_
#define SHILL_NETWORK_NETWORK_CONFIG_H_

#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace shill {

// Properties related to the IP layer used to represent a configuration. All
// fields are optional. A nullopt value means this field is not set.
// TODO(b/232177767): Add more fields and replace IPConfig::Properties.
// TODO(b/232177767): Add unit tests.
struct NetworkConfig {
  // Common properties for IPv4 and IPv6.
  struct RouteProperties {
    // The gateway address in string format.
    std::optional<std::string> gateway;
    // A list of IP blocks in CIDR format that should be included on this
    // network.
    std::optional<std::vector<std::string>> included_route_prefixes;
    // A list of IP blocks in CIDR format that should be excluded from this
    // connection.
    std::optional<std::vector<std::string>> excluded_route_prefixes;
  };

  NetworkConfig();
  ~NetworkConfig();

  // IPv4 address in CIDR format on the interface.
  std::optional<std::string> ipv4_address_cidr;
  RouteProperties ipv4_route;
  // If the interface should be used as default route. Currently this field is
  // mainly used by VPN and thus it is IPv4-only. Since this information can be
  // inferred from included and excluded routes, we plan to remove this later.
  std::optional<bool> ipv4_default_route;

  // IPv6 addresses in CIDR format on the interface.
  std::optional<std::vector<std::string>> ipv6_address_cidrs;
  RouteProperties ipv6_route;

  std::optional<int> mtu;
  std::optional<std::vector<std::string>> dns_servers;
  std::optional<std::vector<std::string>> dns_search_domains;
};

std::ostream& operator<<(std::ostream& stream, const NetworkConfig& config);

}  // namespace shill

#endif  // SHILL_NETWORK_NETWORK_CONFIG_H_
