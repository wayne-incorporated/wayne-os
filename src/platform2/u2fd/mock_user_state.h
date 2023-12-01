// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_MOCK_USER_STATE_H_
#define U2FD_MOCK_USER_STATE_H_

#include "u2fd/client/user_state.h"

#include <optional>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

namespace u2f {

class MockUserState : public UserState {
 public:
  MOCK_METHOD(std::optional<brillo::SecureBlob>, GetUserSecret, (), (override));
  MOCK_METHOD(std::optional<std::string>, GetUser, (), (override));
  MOCK_METHOD(std::optional<std::vector<uint8_t>>, GetCounter, (), (override));
  MOCK_METHOD(bool, IncrementCounter, (), (override));
};

}  // namespace u2f

#endif  // U2FD_MOCK_USER_STATE_H_
