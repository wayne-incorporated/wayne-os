// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/mock_local_device.h"

#include <string>

namespace shill {

MockLocalDevice::MockLocalDevice(Manager* manager,
                                 IfaceType type,
                                 const std::string& link_name,
                                 const std::string& mac_address,
                                 uint32_t phy_index,
                                 const EventCallback& callback)
    : LocalDevice(manager, type, link_name, mac_address, phy_index, callback) {}

MockLocalDevice::~MockLocalDevice() = default;

}  // namespace shill
