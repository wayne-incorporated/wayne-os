// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_MOCK_POWER_MANAGER_CLIENT_H_
#define RMAD_SYSTEM_MOCK_POWER_MANAGER_CLIENT_H_

#include "rmad/system/power_manager_client.h"

#include <gmock/gmock.h>

namespace rmad {

class MockPowerManagerClient : public PowerManagerClient {
 public:
  MockPowerManagerClient() = default;
  MockPowerManagerClient(const MockPowerManagerClient&) = delete;
  MockPowerManagerClient& operator=(const MockPowerManagerClient&) = delete;
  ~MockPowerManagerClient() override = default;

  MOCK_METHOD(bool, Restart, (), (override));
  MOCK_METHOD(bool, Shutdown, (), (override));
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_MOCK_POWER_MANAGER_CLIENT_H_
