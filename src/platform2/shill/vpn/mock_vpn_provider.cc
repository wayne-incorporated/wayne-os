// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/mock_vpn_provider.h"

namespace shill {

MockVPNProvider::MockVPNProvider() : VPNProvider(nullptr) {}

MockVPNProvider::~MockVPNProvider() = default;

}  // namespace shill
