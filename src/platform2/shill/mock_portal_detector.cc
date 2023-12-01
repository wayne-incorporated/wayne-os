// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_portal_detector.h"

#include <base/functional/callback_helpers.h>

namespace shill {

MockPortalDetector::MockPortalDetector()
    : PortalDetector(nullptr, {}, base::DoNothing()) {}

MockPortalDetector::~MockPortalDetector() = default;

}  // namespace shill
