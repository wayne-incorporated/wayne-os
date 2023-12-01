// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_MOCK_ADAPTIVE_CHARGING_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_MOCK_ADAPTIVE_CHARGING_CONTROLLER_H_

#include <vector>

#include <gmock/gmock.h>

#include "power_manager/powerd/policy/adaptive_charging_controller.h"

namespace power_manager::policy {

class MockAdaptiveChargingController
    : public AdaptiveChargingControllerInterface {
 public:
  MockAdaptiveChargingController() = default;
  MockAdaptiveChargingController(const MockAdaptiveChargingController&) =
      delete;
  MockAdaptiveChargingController& operator=(
      const MockAdaptiveChargingController&) = delete;
  ~MockAdaptiveChargingController() override = default;

  MOCK_METHOD(void,
              HandlePolicyChange,
              (const PowerManagementPolicy&),
              (override));

  MOCK_METHOD(void, PrepareForSuspendAttempt, (), (override));

  MOCK_METHOD(void, HandleFullResume, (), (override));

  MOCK_METHOD(void, HandleShutdown, (), (override));

  MOCK_METHOD(void,
              OnPredictionResponse,
              (bool, const std::vector<double>&),
              (override));

  MOCK_METHOD(void, OnPredictionFail, (brillo::Error*), (override));

  MOCK_METHOD(void, OnPowerStatusUpdate, (), (override));
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_MOCK_ADAPTIVE_CHARGING_CONTROLLER_H_
