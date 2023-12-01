// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_SESSION_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_MOCK_SESSION_MANAGEMENT_H_

#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/session_management.h"
#include "libhwsec/status.h"

namespace hwsec {

class BackendTpm2;

class MockSessionManagement : public SessionManagement {
 public:
  MockSessionManagement() = default;
  explicit MockSessionManagement(SessionManagement* on_call)
      : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, FlushInvalidSessions)
        .WillByDefault(
            Invoke(default_, &SessionManagement::FlushInvalidSessions));
  }

  MOCK_METHOD(Status, FlushInvalidSessions, (), (override));

 private:
  SessionManagement* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_SESSION_MANAGEMENT_H_
