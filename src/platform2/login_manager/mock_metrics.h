// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_METRICS_H_
#define LOGIN_MANAGER_MOCK_METRICS_H_

#include "login_manager/login_metrics.h"

#include <base/macros.h>
#include <gmock/gmock.h>

namespace login_manager {
class PolicyKey;

class MockMetrics : public LoginMetrics {
 public:
  MockMetrics();
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;

  ~MockMetrics() override;

  MOCK_METHOD(void, SendConsumerAllowsNewUsers, (bool), (override));
  MOCK_METHOD(void, SendLoginUserType, (bool, bool, bool), (override));
  MOCK_METHOD(bool,
              SendPolicyFilesStatus,
              (const PolicyFilesStatus&),
              (override));
  MOCK_METHOD(void,
              SendStateKeyGenerationStatus,
              (StateKeyGenerationStatus),
              (override));
  MOCK_METHOD(void, RecordStats, (const char*), (override));
  MOCK_METHOD(bool, HasRecordedChromeExec, (), (override));
  MOCK_METHOD(void, SendSessionExitType, (SessionExitType), (override));
  MOCK_METHOD(void, SendBrowserShutdownTime, (base::TimeDelta), (override));
  MOCK_METHOD(void, SendArcBugReportBackupTime, (base::TimeDelta), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_METRICS_H_
