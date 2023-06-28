// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_SESSION_MANAGER_H_
#define LOGIN_MANAGER_MOCK_SESSION_MANAGER_H_

#include "login_manager/session_manager_interface.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace login_manager {

class MockSessionManager : public SessionManagerInterface {
 public:
  MockSessionManager();
  ~MockSessionManager() override;

  MOCK_METHOD(bool, Initialize, (), (override));
  MOCK_METHOD(void, Finalize, (), (override));
  MOCK_METHOD(bool, StartDBusService, (), (override));
  MOCK_METHOD(std::vector<std::string>, GetFeatureFlags, (), (override));
  MOCK_METHOD(void, AnnounceSessionStoppingIfNeeded, (), (override));
  MOCK_METHOD(void, AnnounceSessionStopped, (), (override));
  MOCK_METHOD(bool, ShouldEndSession, (std::string*), (override));
  MOCK_METHOD(void, InitiateDeviceWipe, (const std::string&), (override));
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_SESSION_MANAGER_H_
