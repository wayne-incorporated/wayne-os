// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_SUBPROCESS_H_
#define LOGIN_MANAGER_MOCK_SUBPROCESS_H_

#include <stdint.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/macros.h>
#include <gmock/gmock.h>

#include "login_manager/subprocess.h"

namespace login_manager {

class MockSubprocess : public SubprocessInterface {
 public:
  MockSubprocess();
  MockSubprocess(const MockSubprocess&) = delete;
  MockSubprocess& operator=(const MockSubprocess&) = delete;

  ~MockSubprocess() override;

  MOCK_METHOD(void, UseNewMountNamespace, (), (override));
  MOCK_METHOD(void,
              EnterExistingMountNamespace,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              ForkAndExec,
              (const std::vector<std::string>&,
               const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void, Kill, (int), (override));
  MOCK_METHOD(void, KillEverything, (int), (override));
  MOCK_METHOD(pid_t, GetPid, (), (const, override));
  MOCK_METHOD(void, ClearPid, (), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_SUBPROCESS_H_
