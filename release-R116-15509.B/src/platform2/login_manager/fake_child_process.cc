// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_child_process.h"

namespace login_manager {

FakeChildProcess::FakeChildProcess(pid_t pid,
                                   int status,
                                   SessionManagerService::TestApi api)
    : pid_(pid), exit_status_(status), test_api_(api) {}

FakeChildProcess::~FakeChildProcess() {}

void FakeChildProcess::ScheduleExit() {
  test_api_.ScheduleChildExit(pid_, exit_status_);
}

}  // namespace login_manager
