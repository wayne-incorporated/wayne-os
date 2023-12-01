// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_modem_modem3gpp_proxy.h"

#include <utility>
#include <vector>

#include "shill/testing.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArgs;

namespace shill {
namespace mm1 {

MockModemModem3gppProxy::MockModemModem3gppProxy() {
  ON_CALL(*this, Register(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, Scan(_))
      .WillByDefault(WithArgs<0>(Invoke([](KeyValueStoresCallback callback) {
        std::move(callback).Run(std::vector<KeyValueStore>(),
                                Error(Error::kOperationFailed));
      })));
}

MockModemModem3gppProxy::~MockModemModem3gppProxy() = default;

}  // namespace mm1
}  // namespace shill
