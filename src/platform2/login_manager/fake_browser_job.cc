// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_browser_job.h"

#include "login_manager/fake_child_process.h"

#include <base/check.h>

namespace login_manager {

FakeBrowserJob::FakeBrowserJob(const std::string& name)
    : name_(name), schedule_exit_(true) {}

FakeBrowserJob::FakeBrowserJob(const std::string& name, bool schedule_exit)
    : name_(name), schedule_exit_(schedule_exit) {}

FakeBrowserJob::~FakeBrowserJob() {}

bool FakeBrowserJob::IsGuestSession() {
  return false;
}

bool FakeBrowserJob::ShouldRunBrowser() {
  return should_run_;
}

bool FakeBrowserJob::RunInBackground() {
  if (schedule_exit_) {
    DCHECK(fake_process_.get());
    fake_process_->ScheduleExit();
  }
  return running_ = true;
}

const std::string FakeBrowserJob::GetName() const {
  return name_;
}

pid_t FakeBrowserJob::CurrentPid() const {
  DCHECK(fake_process_.get());
  return (running_ ? fake_process_->pid() : -1);
}

void FakeBrowserJob::ClearPid() {
  running_ = false;
}

}  // namespace login_manager
