// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "shill/ipconfig.h"
#include "shill/mock_resolver.h"
#include "shill/network/network_applier.h"
#include "shill/network/network_priority.h"

using testing::_;
using testing::Mock;
using testing::StrictMock;
using testing::Test;

namespace shill {

class NetworkApplierTest : public Test {
 public:
  NetworkApplierTest()
      : network_applier_(NetworkApplier::CreateForTesting(&resolver_)) {}

 protected:
  StrictMock<MockResolver> resolver_;
  std::unique_ptr<NetworkApplier> network_applier_;
};

TEST_F(NetworkApplierTest, ApplyDNS) {
  NetworkPriority priority;
  priority.is_primary_for_dns = true;
  IPConfig::Properties ipv4_properties;
  ipv4_properties.dns_servers = {"8.8.8.8"};
  ipv4_properties.domain_search = {"domain1"};

  EXPECT_CALL(resolver_, SetDNSFromLists(ipv4_properties.dns_servers,
                                         ipv4_properties.domain_search));
  network_applier_->ApplyDNS(priority, &ipv4_properties, nullptr);

  priority.is_primary_for_dns = false;
  EXPECT_CALL(resolver_, SetDNSFromLists(_, _)).Times(0);
  network_applier_->ApplyDNS(priority, &ipv4_properties, nullptr);
}

TEST_F(NetworkApplierTest, ApplyDNSDomainAdded) {
  NetworkPriority priority;
  priority.is_primary_for_dns = true;
  IPConfig::Properties ipv4_properties;
  ipv4_properties.dns_servers = {"8.8.8.8"};
  const std::string kDomainName("chromium.org");
  ipv4_properties.domain_name = kDomainName;

  std::vector<std::string> expected_domain_search_list = {kDomainName + "."};
  EXPECT_CALL(resolver_, SetDNSFromLists(_, expected_domain_search_list));
  network_applier_->ApplyDNS(priority, &ipv4_properties, nullptr);
}

TEST_F(NetworkApplierTest, ApplyDNSDualStack) {
  NetworkPriority priority;
  priority.is_primary_for_dns = true;
  IPConfig::Properties ipv4_properties;
  ipv4_properties.dns_servers = {"8.8.8.8"};
  ipv4_properties.domain_search = {"domain1", "domain2"};
  IPConfig::Properties ipv6_properties;
  ipv6_properties.dns_servers = {"2001:4860:4860:0:0:0:0:8888"};
  ipv6_properties.domain_search = {"domain3", "domain4"};

  std::vector<std::string> expected_dns = {"2001:4860:4860:0:0:0:0:8888",
                                           "8.8.8.8"};
  std::vector<std::string> expected_dnssl = {"domain3", "domain4", "domain1",
                                             "domain2"};
  EXPECT_CALL(resolver_, SetDNSFromLists(expected_dns, expected_dnssl));
  network_applier_->ApplyDNS(priority, &ipv4_properties, &ipv6_properties);
}

TEST_F(NetworkApplierTest, ApplyDNSDualStackSearchListDedup) {
  NetworkPriority priority;
  priority.is_primary_for_dns = true;
  IPConfig::Properties ipv4_properties;
  ipv4_properties.dns_servers = {"8.8.8.8"};
  ipv4_properties.domain_search = {"domain1", "domain2"};
  IPConfig::Properties ipv6_properties;
  ipv6_properties.dns_servers = {"2001:4860:4860:0:0:0:0:8888"};
  ipv6_properties.domain_search = {"domain1", "domain2"};

  std::vector<std::string> expected_dnssl = {"domain1", "domain2"};
  EXPECT_CALL(resolver_, SetDNSFromLists(_, expected_dnssl));
  network_applier_->ApplyDNS(priority, &ipv4_properties, &ipv6_properties);
}

}  // namespace shill
