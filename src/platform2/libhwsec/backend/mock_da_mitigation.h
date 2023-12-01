// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_DA_MITIGATION_H_
#define LIBHWSEC_BACKEND_MOCK_DA_MITIGATION_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/da_mitigation.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockDAMitigation : public DAMitigation {
 public:
  MockDAMitigation() = default;
  explicit MockDAMitigation(DAMitigation* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsReady)
        .WillByDefault(Invoke(default_, &DAMitigation::IsReady));
    ON_CALL(*this, GetStatus)
        .WillByDefault(Invoke(default_, &DAMitigation::GetStatus));
    ON_CALL(*this, Mitigate)
        .WillByDefault(Invoke(default_, &DAMitigation::Mitigate));
  }

  MOCK_METHOD(StatusOr<bool>, IsReady, (), (override));
  MOCK_METHOD(StatusOr<DAMitigationStatus>, GetStatus, (), (override));
  MOCK_METHOD(Status, Mitigate, (), (override));

 private:
  DAMitigation* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_DA_MITIGATION_H_
