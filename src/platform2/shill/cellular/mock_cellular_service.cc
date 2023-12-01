// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_cellular_service.h"

#include <chromeos/dbus/service_constants.h>

using testing::ReturnRef;

namespace shill {

MockCellularService::MockCellularService(Manager* manager,
                                         const CellularRefPtr& device)
    : CellularService(
          manager, device->imsi(), device->iccid(), device->GetSimCardId()),
      default_activation_state_(kActivationStateUnknown) {
  ON_CALL(*this, activation_state())
      .WillByDefault(ReturnRef(default_activation_state_));
}

MockCellularService::~MockCellularService() = default;

}  // namespace shill
