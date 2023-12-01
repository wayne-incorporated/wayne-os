// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/mock_vpn_service.h"

#include <utility>

#include "shill/vpn/vpn_driver.h"

namespace shill {

MockVPNService::MockVPNService(Manager* manager,
                               std::unique_ptr<VPNDriver> driver)
    : VPNService(manager, std::move(driver)) {}

MockVPNService::~MockVPNService() = default;

}  // namespace shill
