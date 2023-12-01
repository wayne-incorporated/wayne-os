// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/mock_ethernet.h"
#include "shill/ethernet/mock_ethernet_service.h"

#include "shill/ethernet/ethernet.h"  // Needed to pass an EthernetRefPtr.

namespace shill {

MockEthernetService::MockEthernetService(Manager* manager,
                                         base::WeakPtr<Ethernet> ethernet)
    : EthernetService(manager, Properties(ethernet)) {}

MockEthernetService::~MockEthernetService() = default;

}  // namespace shill
