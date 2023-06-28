// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_VPD_PROCESS_IMPL_H_
#define LOGIN_MANAGER_VPD_PROCESS_IMPL_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/callback.h>

#include "login_manager/child_exit_handler.h"
#include "login_manager/subprocess.h"
#include "login_manager/system_utils.h"
#include "login_manager/vpd_process.h"

namespace login_manager {

class VpdProcessImpl : public VpdProcess, public ChildExitHandler {
 public:
  explicit VpdProcessImpl(SystemUtils* system_utils);

  // Ask the managed job to exit. |reason| is a human-readable string that may
  // be logged to describe the reason for the request.
  void RequestJobExit(const std::string& reason);

  // The job must be destroyed within the timeout.
  void EnsureJobExit(base::TimeDelta timeout);

  // Implementation of VpdProcess.
  bool RunInBackground(const KeyValuePairs& updates,
                       bool sync_cache,
                       const CompletionCallback& completion) override;

  // Implementation of ChildExitHandler.
  bool HandleExit(const siginfo_t& status) override;

 private:
  // The subprocess tracked by this job.
  std::unique_ptr<Subprocess> subprocess_;
  SystemUtils* system_utils_;  // Owned by the caller.
  CompletionCallback completion_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_VPD_PROCESS_IMPL_H_
