// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/mock_openvpn_management_server.h"

namespace shill {

MockOpenVPNManagementServer::MockOpenVPNManagementServer()
    : OpenVPNManagementServer(nullptr) {}

MockOpenVPNManagementServer::~MockOpenVPNManagementServer() = default;

}  // namespace shill
