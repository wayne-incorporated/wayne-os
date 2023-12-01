// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/mock_ethernet_provider.h"

namespace shill {

MockEthernetProvider::MockEthernetProvider() : EthernetProvider(nullptr) {}

MockEthernetProvider::~MockEthernetProvider() = default;

}  // namespace shill
