// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_SESSION_STATE_MANAGER_H_
#define BIOD_MOCK_SESSION_STATE_MANAGER_H_

#include <gmock/gmock.h>
#include <string>

#include "biod/session_state_manager.h"

namespace biod {

class MockSessionStateManager : public SessionStateManagerInterface {
 public:
  MOCK_METHOD(std::string, GetPrimaryUser, (), (const, override));
  MOCK_METHOD(bool, RefreshPrimaryUser, (), (override));
  MOCK_METHOD(void, AddObserver, (Observer * observer), (override));
  MOCK_METHOD(void, RemoveObserver, (Observer * observer), (override));
};
}  // namespace biod

#endif  // BIOD_MOCK_SESSION_STATE_MANAGER_H_
