// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_modem_signal_proxy.h"

#include "shill/testing.h"

using testing::_;

namespace shill {
namespace mm1 {

MockModemSignalProxy::MockModemSignalProxy() {
  ON_CALL(*this, Setup(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
  ON_CALL(*this, SetupThresholds(_, _, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<1>());
}

MockModemSignalProxy::~MockModemSignalProxy() = default;

}  // namespace mm1
}  // namespace shill
