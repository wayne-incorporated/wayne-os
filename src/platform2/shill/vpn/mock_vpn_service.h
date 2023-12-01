// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_MOCK_VPN_SERVICE_H_
#define SHILL_VPN_MOCK_VPN_SERVICE_H_

#include <memory>
#include <string>

#include <gmock/gmock.h>

#include "shill/vpn/vpn_driver.h"
#include "shill/vpn/vpn_service.h"

namespace shill {

class MockVPNService : public VPNService {
 public:
  MockVPNService(Manager* manager, std::unique_ptr<VPNDriver> driver);
  MockVPNService(const MockVPNService&) = delete;
  MockVPNService& operator=(const MockVPNService&) = delete;

  ~MockVPNService() override;

  MOCK_METHOD(void, SetState, (ConnectState), (override));
  MOCK_METHOD(void, SetFailure, (ConnectFailure), (override));
  MOCK_METHOD(void, InitDriverPropertyStore, (), (override));

 private:
  base::WeakPtrFactory<MockVPNService> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_MOCK_VPN_SERVICE_H_
