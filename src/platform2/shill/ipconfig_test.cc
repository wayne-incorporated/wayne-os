// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ipconfig.h"

#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"

using testing::_;
using testing::Mock;
using testing::Return;
using testing::Test;

namespace shill {

namespace {
const char kDeviceName[] = "testdevice";
}  // namespace

class IPConfigTest : public Test {
 public:
  IPConfigTest() : ipconfig_(new IPConfig(&control_, kDeviceName)) {}

 protected:
  IPConfigMockAdaptor* GetAdaptor() {
    return static_cast<IPConfigMockAdaptor*>(ipconfig_->adaptor_.get());
  }

  void UpdateProperties(const IPConfig::Properties& properties) {
    ipconfig_->UpdateProperties(properties);
  }

  void ExpectPropertiesEqual(const IPConfig::Properties& properties) {
    EXPECT_EQ(properties.address, ipconfig_->properties().address);
    EXPECT_EQ(properties.subnet_prefix, ipconfig_->properties().subnet_prefix);
    EXPECT_EQ(properties.broadcast_address,
              ipconfig_->properties().broadcast_address);
    EXPECT_EQ(properties.dns_servers.size(),
              ipconfig_->properties().dns_servers.size());
    if (properties.dns_servers.size() ==
        ipconfig_->properties().dns_servers.size()) {
      for (size_t i = 0; i < properties.dns_servers.size(); ++i) {
        EXPECT_EQ(properties.dns_servers[i],
                  ipconfig_->properties().dns_servers[i]);
      }
    }
    EXPECT_EQ(properties.domain_search.size(),
              ipconfig_->properties().domain_search.size());
    if (properties.domain_search.size() ==
        ipconfig_->properties().domain_search.size()) {
      for (size_t i = 0; i < properties.domain_search.size(); ++i) {
        EXPECT_EQ(properties.domain_search[i],
                  ipconfig_->properties().domain_search[i]);
      }
    }
    EXPECT_EQ(properties.gateway, ipconfig_->properties().gateway);
    EXPECT_EQ(properties.blackhole_ipv6,
              ipconfig_->properties().blackhole_ipv6);
    EXPECT_EQ(properties.mtu, ipconfig_->properties().mtu);
  }

  MockControl control_;
  std::unique_ptr<IPConfig> ipconfig_;
};

TEST_F(IPConfigTest, DeviceName) {
  EXPECT_EQ(kDeviceName, ipconfig_->device_name());
}

TEST_F(IPConfigTest, UpdateProperties) {
  IPConfig::Properties properties;
  properties.address = "1.2.3.4";
  properties.subnet_prefix = 24;
  properties.broadcast_address = "11.22.33.44";
  properties.dns_servers = {"10.20.30.40", "20.30.40.50"};
  properties.domain_name = "foo.org";
  properties.domain_search = {"zoo.org", "zoo.com"};
  properties.gateway = "5.6.7.8";
  properties.blackhole_ipv6 = true;
  properties.mtu = 700;
  UpdateProperties(properties);
  ExpectPropertiesEqual(properties);

  // We should reset if ResetProperties is called.
  ipconfig_->ResetProperties();
  ExpectPropertiesEqual(IPConfig::Properties());
}

TEST_F(IPConfigTest, PropertyChanges) {
  IPConfigMockAdaptor* adaptor = GetAdaptor();

  EXPECT_CALL(*adaptor, EmitStringChanged(kAddressProperty, _));
  EXPECT_CALL(*adaptor, EmitStringsChanged(kNameServersProperty, _));
  ipconfig_->ApplyNetworkConfig({});
  Mock::VerifyAndClearExpectations(adaptor);

  IPConfig::Properties ip_properties;
  EXPECT_CALL(*adaptor, EmitStringChanged(kAddressProperty, _));
  EXPECT_CALL(*adaptor, EmitStringsChanged(kNameServersProperty, _));
  UpdateProperties(ip_properties);
  Mock::VerifyAndClearExpectations(adaptor);

  EXPECT_CALL(*adaptor, EmitStringChanged(kAddressProperty, _));
  EXPECT_CALL(*adaptor, EmitStringsChanged(kNameServersProperty, _));
  ipconfig_->ResetProperties();
  Mock::VerifyAndClearExpectations(adaptor);
}

}  // namespace shill
