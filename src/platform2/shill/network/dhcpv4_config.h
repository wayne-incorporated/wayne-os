// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_DHCPV4_CONFIG_H_
#define SHILL_NETWORK_DHCPV4_CONFIG_H_

#include <string>
#include <vector>

#include "shill/ipconfig.h"

namespace shill {

class DHCPv4Config {
 public:
  // Constants used as keys in the configuration got from dhcpcd. Used only
  // internally, make them public for unit tests.
  static constexpr char kConfigurationKeyBroadcastAddress[] =
      "BroadcastAddress";
  static constexpr char kConfigurationKeyClasslessStaticRoutes[] =
      "ClasslessStaticRoutes";
  static constexpr char kConfigurationKeyDNS[] = "DomainNameServers";
  static constexpr char kConfigurationKeyDomainName[] = "DomainName";
  static constexpr char kConfigurationKeyDomainSearch[] = "DomainSearch";
  static constexpr char kConfigurationKeyHostname[] = "Hostname";
  static constexpr char kConfigurationKeyIPAddress[] = "IPAddress";
  static constexpr char kConfigurationKeyiSNSOptionData[] = "iSNSOptionData";
  static constexpr char kConfigurationKeyLeaseTime[] = "DHCPLeaseTime";
  static constexpr char kConfigurationKeyMTU[] = "InterfaceMTU";
  static constexpr char kConfigurationKeyRouters[] = "Routers";
  static constexpr char kConfigurationKeySubnetCIDR[] = "SubnetCIDR";
  static constexpr char kConfigurationKeyVendorEncapsulatedOptions[] =
      "VendorEncapsulatedOptions";
  static constexpr char kConfigurationKeyWebProxyAutoDiscoveryUrl[] =
      "WebProxyAutoDiscoveryUrl";

  // Parses |configuration| into |properties|. Returns true on success, and
  // false otherwise.
  static bool ParseConfiguration(const KeyValueStore& configuration,
                                 IPConfig::Properties* properties);

  // Parses |classless_routes| into |properties|.  Sets the default gateway
  // if one is supplied and |properties| does not already contain one.  It
  // also sets the "routes" parameter of the IPConfig properties for all
  // routes not converted into the default gateway.  Returns true on
  // success, and false otherwise.
  static bool ParseClasslessStaticRoutes(const std::string& classless_routes,
                                         IPConfig::Properties* properties);

  // Returns the string representation of the IP address |address|, or an
  // empty string on failure.
  static std::string GetIPv4AddressString(unsigned int address);
};

}  // namespace shill

#endif  // SHILL_NETWORK_DHCPV4_CONFIG_H_
