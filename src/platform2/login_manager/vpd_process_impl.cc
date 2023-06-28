// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/vpd_process_impl.h"

#include <string>
#include <utility>
#include <vector>

#include "metrics/metrics_library.h"

#include <base/check.h>

namespace {

constexpr char kVpdUpdateMetric[] = "Enterprise.VpdUpdateStatus";

}  // namespace

namespace login_manager {

VpdProcessImpl::VpdProcessImpl(SystemUtils* system_utils)
    : system_utils_(system_utils) {
  DCHECK(system_utils_);
}

void VpdProcessImpl::RequestJobExit(const std::string& reason) {
  if (subprocess_ && subprocess_->GetPid() > 0)
    subprocess_->Kill(SIGTERM);
}

void VpdProcessImpl::EnsureJobExit(base::TimeDelta timeout) {
  if (subprocess_) {
    if (subprocess_->GetPid() < 0)
      return;
    if (!system_utils_->ProcessGroupIsGone(subprocess_->GetPid(), timeout)) {
      subprocess_->KillEverything(SIGABRT);
      DLOG(INFO) << "Child process was killed.";
    }
  }
}

bool VpdProcessImpl::RunInBackground(const KeyValuePairs& updates,
                                     bool ignore_cache,
                                     const CompletionCallback& completion) {
  subprocess_.reset(new Subprocess(0 /*root*/, system_utils_));

  std::vector<std::string> argv = {"/usr/sbin/update_rw_vpd"};
  for (const auto& entry : updates) {
    argv.push_back(entry.first);
    argv.push_back(entry.second);
  }

  std::vector<std::string> env;
  if (ignore_cache) {
    env.push_back("VPD_IGNORE_CACHE=1");
  }

  if (!subprocess_->ForkAndExec(argv, env)) {
    // The caller remains responsible for running |completion|.
    return false;
  }

  // |completion_| will be run when the job exits.
  completion_ = completion;
  return true;
}

bool VpdProcessImpl::HandleExit(const siginfo_t& info) {
  if (!subprocess_ || subprocess_->GetPid() <= 0 ||
      subprocess_->GetPid() != info.si_pid) {
    return false;
  }

  MetricsLibrary metrics;
  metrics.SendSparseToUMA(kVpdUpdateMetric, info.si_status);

  const bool success = (info.si_status == 0);
  LOG_IF(ERROR, !success) << "Failed to update VPD, code = " << info.si_status;

  // Reset the completion to ensure we won't call it again.
  if (!completion_.is_null())
    std::move(completion_).Run(success);
  return true;
}

}  // namespace login_manager
