// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_FAKE_CHILD_PROCESS_H_
#define LOGIN_MANAGER_FAKE_CHILD_PROCESS_H_

#include <sys/types.h>

#include "login_manager/session_manager_service.h"

namespace login_manager {

class FakeChildProcess {
 public:
  // Fakes a child process with a pid and an exit status.
  // |status| should be constructed using macros defined in
  // <bits/waitstatus.h>.
  FakeChildProcess(pid_t pid, int status, SessionManagerService::TestApi api);
  FakeChildProcess(const FakeChildProcess&) = delete;
  FakeChildProcess& operator=(const FakeChildProcess&) = delete;

  ~FakeChildProcess();

  pid_t pid() { return pid_; }

  // Schedule an exit for |pid_|, with status of |exit_status_|.
  // Calls through |test_api_| to communicate with the SessionManagerService.
  void ScheduleExit();

 private:
  pid_t pid_;
  int exit_status_;
  SessionManagerService::TestApi test_api_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_FAKE_CHILD_PROCESS_H_
