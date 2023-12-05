// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_PROCESS_MANAGER_SERVICE_H_
#define LOGIN_MANAGER_MOCK_PROCESS_MANAGER_SERVICE_H_

#include "login_manager/process_manager_service_interface.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace login_manager {
class GeneratorJobInterface;

class MockProcessManagerService : public ProcessManagerServiceInterface {
 public:
  MockProcessManagerService();
  ~MockProcessManagerService() override;

  MOCK_METHOD(void, ScheduleShutdown, (), (override));
  MOCK_METHOD(void, RunBrowser, (), (override));
  MOCK_METHOD(void, AbortBrowserForHang, (), (override));
  MOCK_METHOD(void,
              SetBrowserTestArgs,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void,
              SetBrowserArgs,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void,
              SetBrowserAdditionalEnvironmentalVariables,
              (const std::vector<std::string>& env_vars),
              (override));
  MOCK_METHOD(void, RestartBrowser, (), (override));
  MOCK_METHOD(void,
              SetBrowserSessionForUser,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void,
              SetFlagsForUser,
              (const std::string&, const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void,
              SetFeatureFlagsForUser,
              (const std::string&,
               const std::vector<std::string>&,
               (const std::map<std::string, std::string>&)),
              (override));
  MOCK_METHOD(void,
              SetBrowserDataMigrationArgsForUser,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void,
              SetBrowserDataBackwardMigrationArgsForUser,
              (const std::string&),
              (override));
  MOCK_METHOD(bool, IsBrowser, (pid_t), (override));
  MOCK_METHOD(std::optional<pid_t>, GetBrowserPid, (), (const override));
  MOCK_METHOD(base::TimeTicks, GetLastBrowserRestartTime, (), (override));
  MOCK_METHOD(void, SetMultiUserSessionStarted, (), (override));
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_PROCESS_MANAGER_SERVICE_H_
