// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_POLICY_MOCK_LIBPOLICY_H_
#define LIBBRILLO_POLICY_MOCK_LIBPOLICY_H_

#include <gmock/gmock.h>
#include <set>

#include "policy/libpolicy.h"

#pragma GCC visibility push(default)

namespace policy {

// This is a generic mock of the PolicyProvider class.
class MockPolicyProvider : public PolicyProvider {
 public:
  MockPolicyProvider() = default;
  MockPolicyProvider(const MockPolicyProvider&) = delete;
  MockPolicyProvider& operator=(const MockPolicyProvider&) = delete;

  ~MockPolicyProvider() override = default;

  MOCK_METHOD(bool, Reload, (), (override));
  MOCK_METHOD(bool, device_policy_is_loaded, (), (const, override));
  MOCK_METHOD(const DevicePolicy&, GetDevicePolicy, (), (const, override));
  MOCK_METHOD(bool, IsConsumerDevice, (), (const, override));
};

}  // namespace policy

#pragma GCC visibility pop

#endif  // LIBBRILLO_POLICY_MOCK_LIBPOLICY_H_
