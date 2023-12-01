// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/mock_eap_listener.h"

namespace shill {

MockEapListener::MockEapListener() : EapListener(0, "eth0") {}

MockEapListener::~MockEapListener() = default;

}  // namespace shill
