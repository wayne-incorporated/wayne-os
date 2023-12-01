// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/mock_passpoint_credentials.h"

#include <string>

#include "shill/wifi/passpoint_credentials.h"

namespace shill {

MockPasspointCredentials::MockPasspointCredentials(std::string id)
    : PasspointCredentials(id) {}

MockPasspointCredentials::~MockPasspointCredentials() = default;

}  // namespace shill
