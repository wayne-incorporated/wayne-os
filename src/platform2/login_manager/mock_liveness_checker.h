// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_LIVENESS_CHECKER_H_
#define LOGIN_MANAGER_MOCK_LIVENESS_CHECKER_H_

#include "login_manager/liveness_checker.h"

#include <base/macros.h>
#include <gmock/gmock.h>

namespace login_manager {

class MockLivenessChecker : public LivenessChecker {
 public:
  MockLivenessChecker();
  MockLivenessChecker(const MockLivenessChecker&) = delete;
  MockLivenessChecker& operator=(const MockLivenessChecker&) = delete;

  ~MockLivenessChecker() override;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, IsRunning, (), (override));
  MOCK_METHOD(void, DisableAborting, (), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_LIVENESS_CHECKER_H_
