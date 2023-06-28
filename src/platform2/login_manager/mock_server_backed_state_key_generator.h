// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_SERVER_BACKED_STATE_KEY_GENERATOR_H_
#define LOGIN_MANAGER_MOCK_SERVER_BACKED_STATE_KEY_GENERATOR_H_

#include <base/macros.h>
#include <gmock/gmock.h>

#include "login_manager/server_backed_state_key_generator.h"

namespace login_manager {

class MockServerBackedStateKeyGenerator : public ServerBackedStateKeyGenerator {
 public:
  MockServerBackedStateKeyGenerator(SystemUtils* system_utils,
                                    LoginMetrics* metrics)
      : ServerBackedStateKeyGenerator(system_utils, metrics) {}
  MockServerBackedStateKeyGenerator(const MockServerBackedStateKeyGenerator&) =
      delete;
  MockServerBackedStateKeyGenerator& operator=(
      const MockServerBackedStateKeyGenerator&) = delete;

  ~MockServerBackedStateKeyGenerator() override {}

  MOCK_METHOD(void, RequestStateKeys, (const StateKeyCallback&), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_SERVER_BACKED_STATE_KEY_GENERATOR_H_
