// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_modem_proxy.h"

#include "shill/testing.h"

using testing::_;
using testing::Invoke;
using testing::WithArgs;

namespace shill {
namespace mm1 {

MockModemProxy::MockModemProxy() {
  ON_CALL(*this, Enable(_, _, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, CreateBearer(_, _, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<RpcIdentifierCallback>)));
  ON_CALL(*this, DeleteBearer(_, _, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, Reset(_, _))
      .WillByDefault(
          WithArgs<0>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, FactoryReset(_, _, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, SetCurrentCapabilities(_, _, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, SetCurrentModes(_, _, _, _))
      .WillByDefault(
          WithArgs<2>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, Command(_, _, _, _))
      .WillByDefault(
          WithArgs<2>(Invoke(ReturnOperationFailed<StringCallback>)));
  ON_CALL(*this, SetPowerState(_, _, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
}

MockModemProxy::~MockModemProxy() = default;

}  // namespace mm1
}  // namespace shill
