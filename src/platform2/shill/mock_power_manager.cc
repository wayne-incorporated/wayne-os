// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_power_manager.h"

namespace shill {

MockPowerManager::MockPowerManager(ControlInterface* control_interface)
    : PowerManager(control_interface) {}

MockPowerManager::~MockPowerManager() = default;

}  // namespace shill
