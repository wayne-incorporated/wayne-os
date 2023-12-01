// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_CONFIG_H_
#define LIBHWSEC_BACKEND_MOCK_CONFIG_H_

#include <string>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/config.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class MockConfig : public Config {
 public:
  MockConfig() = default;
  explicit MockConfig(Config* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, ToOperationPolicy)
        .WillByDefault(Invoke(default_, &Config::ToOperationPolicy));
    ON_CALL(*this, SetCurrentUser)
        .WillByDefault(Invoke(default_, &Config::SetCurrentUser));
    ON_CALL(*this, IsCurrentUserSet)
        .WillByDefault(Invoke(default_, &Config::IsCurrentUserSet));
  }

  MOCK_METHOD(StatusOr<OperationPolicy>,
              ToOperationPolicy,
              (const OperationPolicySetting& policy),
              (override));
  MOCK_METHOD(Status,
              SetCurrentUser,
              (const std::string& current_user),
              (override));
  MOCK_METHOD(StatusOr<bool>, IsCurrentUserSet, (), (override));
  MOCK_METHOD(StatusOr<DeviceConfigSettings::BootModeSetting::Mode>,
              GetCurrentBootMode,
              (),
              (override));

 private:
  Config* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_CONFIG_H_
