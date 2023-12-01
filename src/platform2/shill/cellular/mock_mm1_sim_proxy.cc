// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mm1_sim_proxy.h"

#include "shill/testing.h"

using testing::_;
using testing::Invoke;
using testing::WithArgs;

namespace shill {
namespace mm1 {

MockSimProxy::MockSimProxy() {
  ON_CALL(*this, SendPin(_, _))
      .WillByDefault(
          WithArgs<1>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, SendPuk(_, _, _))
      .WillByDefault(
          WithArgs<2>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, EnablePin(_, _, _))
      .WillByDefault(
          WithArgs<2>(Invoke(ReturnOperationFailed<ResultCallback>)));
  ON_CALL(*this, ChangePin(_, _, _))
      .WillByDefault(
          WithArgs<2>(Invoke(ReturnOperationFailed<ResultCallback>)));
}

MockSimProxy::~MockSimProxy() = default;

}  // namespace mm1
}  // namespace shill
