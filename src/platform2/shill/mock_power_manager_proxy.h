// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_POWER_MANAGER_PROXY_H_
#define SHILL_MOCK_POWER_MANAGER_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/power_manager_proxy_interface.h"

namespace shill {

class MockPowerManagerProxy : public PowerManagerProxyInterface {
 public:
  MockPowerManagerProxy();
  MockPowerManagerProxy(const MockPowerManagerProxy&) = delete;
  MockPowerManagerProxy& operator=(const MockPowerManagerProxy&) = delete;

  ~MockPowerManagerProxy() override;

  MOCK_METHOD(bool,
              RegisterSuspendDelay,
              (base::TimeDelta, const std::string&, int*),
              (override));
  MOCK_METHOD(bool, UnregisterSuspendDelay, (int), (override));
  MOCK_METHOD(bool, ReportSuspendReadiness, (int, int), (override));
  MOCK_METHOD(bool,
              RegisterDarkSuspendDelay,
              (base::TimeDelta, const std::string&, int*),
              (override));
  MOCK_METHOD(bool, UnregisterDarkSuspendDelay, (int), (override));
  MOCK_METHOD(bool, ReportDarkSuspendReadiness, (int, int), (override));
  MOCK_METHOD(bool,
              RecordDarkResumeWakeReason,
              (const std::string&),
              (override));
  MOCK_METHOD(void,
              ChangeRegDomain,
              (power_manager::WifiRegDomainDbus),
              (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_POWER_MANAGER_PROXY_H_
