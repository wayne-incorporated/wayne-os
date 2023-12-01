// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_device_info.h"

namespace shill {

MockDeviceInfo::MockDeviceInfo(Manager* manager) : DeviceInfo(manager) {}

MockDeviceInfo::~MockDeviceInfo() = default;

}  // namespace shill
