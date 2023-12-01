// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_MOCK_DEVICE_USER_H_
#define SECAGENTD_TEST_MOCK_DEVICE_USER_H_

#include <string>

#include "base/time/time.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "secagentd/device_user.h"

namespace secagentd::testing {

class MockDeviceUser : public DeviceUserInterface {
 public:
  MOCK_METHOD(void, RegisterSessionChangeHandler, (), (override));
  MOCK_METHOD(std::string, GetDeviceUser, (), (override));
};
}  // namespace secagentd::testing

#endif  // SECAGENTD_TEST_MOCK_DEVICE_USER_H_
