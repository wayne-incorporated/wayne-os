// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/mock_wifi_phy.h"

namespace shill {

MockWiFiPhy::MockWiFiPhy(uint32_t phy_index) : WiFiPhy(phy_index) {}

MockWiFiPhy::~MockWiFiPhy() = default;

}  // namespace shill
