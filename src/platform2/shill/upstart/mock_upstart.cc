// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/upstart/mock_upstart.h"

namespace shill {

MockUpstart::MockUpstart(ControlInterface* control_interface)
    : Upstart(control_interface) {}

MockUpstart::~MockUpstart() = default;

}  // namespace shill
