// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_POWER_MANAGER_H_
#define SHILL_MOCK_POWER_MANAGER_H_

#include <gmock/gmock.h>

#include "shill/power_manager.h"

namespace shill {

class ControlInterface;

class MockPowerManager : public PowerManager {
 public:
  explicit MockPowerManager(ControlInterface* control_interface);
  MockPowerManager(const MockPowerManager&) = delete;
  MockPowerManager& operator=(const MockPowerManager&) = delete;

  ~MockPowerManager() override;

  MOCK_METHOD(bool, ReportSuspendReadiness, (), (override));
  MOCK_METHOD(bool, ReportDarkSuspendReadiness, (), (override));
  MOCK_METHOD(void,
              Start,
              (base::TimeDelta,
               const PowerManager::SuspendImminentCallback&,
               const PowerManager::SuspendDoneCallback&,
               const PowerManager::DarkSuspendImminentCallback&),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, ChangeRegDomain, (nl80211_dfs_regions), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_POWER_MANAGER_H_
