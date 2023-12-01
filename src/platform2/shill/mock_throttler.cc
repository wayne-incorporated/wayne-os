// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_throttler.h"

namespace shill {

MockThrottler::MockThrottler() : Throttler(nullptr, nullptr) {}

MockThrottler::~MockThrottler() = default;
}  // namespace shill
