// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_MOCK_DHCP_PROXY_H_
#define SHILL_NETWORK_MOCK_DHCP_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/network/dhcp_proxy_interface.h"

namespace shill {

class MockDHCPProxy : public DHCPProxyInterface {
 public:
  MockDHCPProxy();
  MockDHCPProxy(const MockDHCPProxy&) = delete;
  MockDHCPProxy& operator=(const MockDHCPProxy&) = delete;

  ~MockDHCPProxy() override;

  MOCK_METHOD(void, Rebind, (const std::string&), (override));
  MOCK_METHOD(void, Release, (const std::string&), (override));
};

}  // namespace shill

#endif  // SHILL_NETWORK_MOCK_DHCP_PROXY_H_
