// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_METRICS_H_
#define LOGIN_MANAGER_MOCK_METRICS_H_

#include "login_manager/login_metrics.h"

#include <gmock/gmock.h>

namespace login_manager {
class PolicyKey;

class MockMetrics : public LoginMetrics {
 public:
  MockMetrics();
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;

  ~MockMetrics() override;

  MOCK_METHOD(void,
              SendStateKeyGenerationStatus,
              (StateKeyGenerationStatus),
              (override));
  MOCK_METHOD(void, RecordStats, (const char*), (override));
  MOCK_METHOD(bool, HasRecordedChromeExec, (), (override));
  MOCK_METHOD(void, SendSessionExitType, (SessionExitType), (override));
  MOCK_METHOD(void, SendBrowserShutdownTime, (base::TimeDelta), (override));
  MOCK_METHOD(void, SendLivenessPingResult, (bool success), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_METRICS_H_
