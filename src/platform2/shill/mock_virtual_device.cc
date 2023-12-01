// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_virtual_device.h"

namespace shill {

MockVirtualDevice::MockVirtualDevice(Manager* manager,
                                     const std::string& link_name,
                                     int interface_index,
                                     Technology technology)
    : VirtualDevice(manager, link_name, interface_index, technology) {}

MockVirtualDevice::~MockVirtualDevice() = default;

}  // namespace shill
