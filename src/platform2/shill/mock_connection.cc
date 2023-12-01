// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_connection.h"

#include "shill/ipconfig.h"

namespace shill {

MockConnection::MockConnection()
    : Connection(0, std::string(), false, Technology::kUnknown) {}

MockConnection::~MockConnection() = default;

}  // namespace shill
