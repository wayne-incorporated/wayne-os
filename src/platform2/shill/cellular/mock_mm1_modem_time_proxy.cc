// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_modem_time_proxy.h"

#include "shill/testing.h"

using testing::_;

namespace shill {
namespace mm1 {

MockModemTimeProxy::MockModemTimeProxy() {
  ON_CALL(*this, GetNetworkTime(_, _, _))
      .WillByDefault(SetOperationFailedInArgumentAndWarn<0>());
}

MockModemTimeProxy::~MockModemTimeProxy() = default;

}  // namespace mm1
}  // namespace shill
