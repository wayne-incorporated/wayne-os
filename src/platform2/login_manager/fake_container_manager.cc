// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_container_manager.h"

namespace login_manager {

FakeContainerManager::FakeContainerManager(pid_t pid) : pid_(pid) {}

bool FakeContainerManager::HandleExit(const siginfo_t& status) {
  return running_ && status.si_pid == pid_;
}

void FakeContainerManager::RequestJobExit(ArcContainerStopReason reason) {
  LOG_IF(FATAL, !running_) << "Trying to stop an already stopped container";
  running_ = false;
  exit_callback_.Run(pid_, reason);
}

void FakeContainerManager::EnsureJobExit(base::TimeDelta timeout) {}

bool FakeContainerManager::StartContainer(const std::vector<std::string>& env,
                                          const ExitCallback& exit_callback) {
  LOG_IF(FATAL, running_) << "Trying to start an already started container";
  exit_callback_ = exit_callback;
  running_ = true;
  return true;
}

StatefulMode FakeContainerManager::GetStatefulMode() const {
  return stateful_mode_;
}

void FakeContainerManager::SetStatefulMode(StatefulMode mode) {
  stateful_mode_ = mode;
}

bool FakeContainerManager::GetContainerPID(pid_t* pid_out) const {
  if (!running_)
    return false;
  *pid_out = pid_;
  return true;
}

void FakeContainerManager::SimulateCrash() {
  LOG_IF(FATAL, !running_) << "Trying to crash an already stopped container";
  running_ = false;
  exit_callback_.Run(pid_, ArcContainerStopReason::CRASH);
}

}  // namespace login_manager
