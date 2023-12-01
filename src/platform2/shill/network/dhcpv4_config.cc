// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/dhcpv4_config.h"

#include <arpa/inet.h>

#include <iterator>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/net/ip_address.h"
#include "shill/network/dhcp_provider.h"
#include "shill/technology.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDHCP;
}  // namespace Logging

// static
std::string DHCPv4Config::GetIPv4AddressString(unsigned int address) {
  char str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, str, std::size(str))) {
    return str;
  }
  LOG(ERROR) << "Unable to convert IPv4 address to string: " << address;
  return "";
}

// static
bool DHCPv4Config::ParseClasslessStaticRoutes(
    const std::string& classless_routes, IPConfig::Properties* properties) {
  if (classless_routes.empty()) {
    // It is not an error for this string to be empty.
    return true;
  }

  const auto route_strings = base::SplitString(
      classless_routes, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (route_strings.size() % 2) {
    LOG(ERROR) << "In " << __func__ << ": Size of route_strings array "
               << "is a non-even number: " << route_strings.size();
    return false;
  }

  std::vector<IPConfig::Route> routes;
  auto route_iterator = route_strings.begin();
  // Classless routes are a space-delimited array of
  // "destination/prefix gateway" values.  As such, we iterate twice
  // for each pass of the loop below.
  while (route_iterator != route_strings.end()) {
    const auto& destination_as_string = *route_iterator;
    route_iterator++;
    const auto destination = IPAddress::CreateFromPrefixString(
        destination_as_string, IPAddress::kFamilyIPv4);
    if (!destination.has_value()) {
      LOG(ERROR) << "In " << __func__ << ": Expected an IP address/prefix "
                 << "but got an unparsable: " << destination_as_string;
      return false;
    }

    CHECK(route_iterator != route_strings.end());
    const auto& gateway_as_string = *route_iterator;
    route_iterator++;
    const auto gateway =
        IPAddress::CreateFromString(gateway_as_string, IPAddress::kFamilyIPv4);
    if (!gateway.has_value()) {
      LOG(ERROR) << "In " << __func__ << ": Expected a router IP address "
                 << "but got an unparsable: " << gateway_as_string;
      return false;
    }

    if (destination->prefix() == 0 && properties->gateway.empty()) {
      // If a default route is provided in the classless parameters and
      // we don't already have one, apply this as the default route.
      SLOG(2) << "In " << __func__ << ": Setting default gateway to "
              << gateway_as_string;
      CHECK(gateway->IntoString(&properties->gateway));
    } else {
      IPConfig::Route route;
      CHECK(destination->IntoString(&route.host));
      route.prefix = destination->prefix();
      CHECK(gateway->IntoString(&route.gateway));
      routes.push_back(route);
      SLOG(2) << "In " << __func__ << ": Adding route to to "
              << destination_as_string << " via " << gateway_as_string;
    }
  }

  properties->dhcp_classless_static_routes.swap(routes);

  return true;
}

// static
bool DHCPv4Config::ParseConfiguration(const KeyValueStore& configuration,
                                      IPConfig::Properties* properties) {
  SLOG(2) << __func__;
  properties->method = kTypeDHCP;
  properties->address_family = IPAddress::kFamilyIPv4;
  std::string classless_static_routes;
  bool default_gateway_parse_error = false;
  for (const auto& it : configuration.properties()) {
    const auto& key = it.first;
    const brillo::Any& value = it.second;
    SLOG(2) << "Processing key: " << key;
    if (key == kConfigurationKeyIPAddress) {
      properties->address = GetIPv4AddressString(value.Get<uint32_t>());
      if (properties->address.empty()) {
        return false;
      }
    } else if (key == kConfigurationKeySubnetCIDR) {
      properties->subnet_prefix = value.Get<uint8_t>();
    } else if (key == kConfigurationKeyBroadcastAddress) {
      properties->broadcast_address =
          GetIPv4AddressString(value.Get<uint32_t>());
      if (properties->broadcast_address.empty()) {
        return false;
      }
    } else if (key == kConfigurationKeyRouters) {
      const auto& routers = value.Get<std::vector<uint32_t>>();
      if (routers.empty()) {
        LOG(ERROR) << "No routers provided.";
        default_gateway_parse_error = true;
      } else {
        properties->gateway = GetIPv4AddressString(routers[0]);
        if (properties->gateway.empty()) {
          LOG(ERROR) << "Failed to parse router parameter provided.";
          default_gateway_parse_error = true;
        }
      }
    } else if (key == kConfigurationKeyDNS) {
      const auto& servers = value.Get<std::vector<uint32_t>>();
      for (auto it = servers.begin(); it != servers.end(); ++it) {
        std::string server = GetIPv4AddressString(*it);
        if (server.empty()) {
          return false;
        }
        properties->dns_servers.push_back(std::move(server));
      }
    } else if (key == kConfigurationKeyDomainName) {
      properties->domain_name = value.Get<std::string>();
    } else if (key == kConfigurationKeyDomainSearch) {
      properties->domain_search = value.Get<std::vector<std::string>>();
    } else if (key == kConfigurationKeyMTU) {
      int mtu = value.Get<uint16_t>();
      if (mtu > IPConfig::kMinIPv4MTU) {
        properties->mtu = mtu;
      }
    } else if (key == kConfigurationKeyClasslessStaticRoutes) {
      classless_static_routes = value.Get<std::string>();
    } else if (key == kConfigurationKeyVendorEncapsulatedOptions) {
      properties->vendor_encapsulated_options = value.Get<ByteArray>();
    } else if (key == kConfigurationKeyWebProxyAutoDiscoveryUrl) {
      properties->web_proxy_auto_discovery = value.Get<std::string>();
    } else if (key == kConfigurationKeyLeaseTime) {
      properties->lease_duration_seconds = value.Get<uint32_t>();
    } else if (key == kConfigurationKeyiSNSOptionData) {
      properties->isns_option_data = value.Get<ByteArray>();
    } else {
      SLOG(2) << "Key ignored.";
    }
  }
  ParseClasslessStaticRoutes(classless_static_routes, properties);
  if (default_gateway_parse_error && properties->gateway.empty()) {
    return false;
  }
  return true;
}

}  // namespace shill
