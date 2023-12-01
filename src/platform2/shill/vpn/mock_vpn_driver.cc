// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/mock_vpn_driver.h"

#include "shill/vpn/vpn_provider.h"

namespace shill {

MockVPNDriver::MockVPNDriver()
    : VPNDriver(nullptr, nullptr, VPNType::kIKEv2, nullptr, 0) {}

MockVPNDriver::MockVPNDriver(VPNType vpn_type)
    : VPNDriver(nullptr, nullptr, vpn_type, nullptr, 0) {}

MockVPNDriver::~MockVPNDriver() = default;

MockVPNDriverEventHandler::MockVPNDriverEventHandler() = default;

MockVPNDriverEventHandler::~MockVPNDriverEventHandler() = default;

}  // namespace shill
