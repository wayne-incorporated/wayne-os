// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/mock_slaac_controller.h"

#include "shill/network/slaac_controller.h"

namespace shill {

MockSLAACController::MockSLAACController()
    : SLAACController(0, nullptr, nullptr, nullptr) {}

MockSLAACController::~MockSLAACController() = default;

}  // namespace shill
