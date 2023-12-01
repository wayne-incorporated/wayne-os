// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_MOCK_VPN_PROVIDER_H_
#define SHILL_VPN_MOCK_VPN_PROVIDER_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/vpn/vpn_provider.h"

namespace shill {

class MockVPNProvider : public VPNProvider {
 public:
  MockVPNProvider();
  MockVPNProvider(const MockVPNProvider&) = delete;
  MockVPNProvider& operator=(const MockVPNProvider&) = delete;

  ~MockVPNProvider() override;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, HasActiveService, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_VPN_MOCK_VPN_PROVIDER_H_
