// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/mock_openvpn_driver.h"

namespace shill {

MockOpenVPNDriver::MockOpenVPNDriver(Manager* manager,
                                     ProcessManager* process_manager)
    : OpenVPNDriver(manager, process_manager) {}

MockOpenVPNDriver::~MockOpenVPNDriver() = default;

}  // namespace shill
