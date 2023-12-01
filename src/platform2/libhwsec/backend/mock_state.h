// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_STATE_H_
#define LIBHWSEC_BACKEND_MOCK_STATE_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/state.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockState : public State {
 public:
  MockState() = default;
  explicit MockState(State* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsEnabled)
        .WillByDefault(Invoke(default_, &State::IsEnabled));
    ON_CALL(*this, IsReady).WillByDefault(Invoke(default_, &State::IsReady));
    ON_CALL(*this, Prepare).WillByDefault(Invoke(default_, &State::Prepare));
    ON_CALL(*this, WaitUntilReady)
        .WillByDefault(Invoke(default_, &State::WaitUntilReady));
  }

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (override));
  MOCK_METHOD(StatusOr<bool>, IsReady, (), (override));
  MOCK_METHOD(Status, Prepare, (), (override));
  MOCK_METHOD(void,
              WaitUntilReady,
              (base::OnceCallback<void(Status)> callback),
              (override));

 private:
  State* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_STATE_H_
