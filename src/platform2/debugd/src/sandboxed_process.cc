// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/sandboxed_process.h"

#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace debugd {

namespace {

const size_t kMaxWaitAttempts = 3;
const unsigned int kDelayUSec = 1000;

const char kMiniJail[] = "/sbin/minijail0";

// waitpid(2) with a timeout of kMaxWaitAttempts * kDelayUSec.
bool waitpid_awhile(pid_t pid) {
  DCHECK_GT(pid, 0);
  for (size_t attempt = 0; attempt < kMaxWaitAttempts; ++attempt) {
    pid_t res = waitpid(pid, nullptr, WNOHANG);
    if (res > 0) {
      return true;
    }
    if (res < 0) {
      PLOG(ERROR) << "waitpid(" << pid << ") failed";
      return false;
    }
    usleep(kDelayUSec);
  }
  return false;
}

}  // namespace

const char SandboxedProcess::kDefaultUser[] = "debugd";
const char SandboxedProcess::kDefaultGroup[] = "debugd";

SandboxedProcess::SandboxedProcess()
    : sandboxing_(true),
      access_root_mount_ns_(false),
      set_capabilities_(false),
      inherit_usergroups_(false),
      user_(kDefaultUser),
      group_(kDefaultGroup) {}

bool SandboxedProcess::Init(
    const std::vector<std::string>& minijail_extra_args) {
  if (sandboxing_ && (user_.empty() || group_.empty())) {
    // Cannot sandbox without user/group.
    return false;
  }

  if (set_capabilities_ && (!sandboxing_ || user_ == "root")) {
    // Restricting capabilities requires dropping root.
    return false;
  }

  AddArg(kMiniJail);
  // Enter a new mount namespace. This is done for every process to avoid
  // affecting the original mount namespace.
  AddArg("-v");

  if (sandboxing_) {
    if (user_ != "root") {
      AddArg("-u");
      AddArg(user_);
    }
    if (group_ != "root") {
      AddArg("-g");
      AddArg(group_);
    }
    if (inherit_usergroups_) {
      AddArg("-G");
    }
    if (set_capabilities_) {
      AddStringOption("-c",
                      base::StringPrintf("0x%" PRIx64, capabilities_mask_));
    }
  }

  if (access_root_mount_ns_) {
    // Enter root mount namespace.
    AddStringOption("-V", "/proc/1/ns/mnt");
  }

  if (!seccomp_filter_policy_file_.empty()) {
    AddStringOption("-S", seccomp_filter_policy_file_);

    // Whenever we use a seccomp filter, we want no-new-privs so we can apply
    // the policy after dropping other privs.
    AddArg("-n");
  }

  for (const auto& env_var : env_vars_) {
    AddArg("--env-add");
    AddArg(base::JoinString({env_var.first, env_var.second}, "="));
  }

  for (const auto& arg : minijail_extra_args)
    AddArg(arg);

  AddArg("--");

  return true;
}

bool SandboxedProcess::Init() {
  return Init({});
}

void SandboxedProcess::DisableSandbox() {
  sandboxing_ = false;
}

void SandboxedProcess::SandboxAs(const std::string& user,
                                 const std::string& group) {
  sandboxing_ = true;
  user_ = user;
  group_ = group;
}

void SandboxedProcess::InheritUsergroups() {
  inherit_usergroups_ = true;
}

void SandboxedProcess::SetCapabilities(uint64_t capabilities_mask) {
  set_capabilities_ = true;
  capabilities_mask_ = capabilities_mask;
}

void SandboxedProcess::SetSeccompFilterPolicyFile(const std::string& path) {
  seccomp_filter_policy_file_ = path;
}

void SandboxedProcess::AllowAccessRootMountNamespace() {
  access_root_mount_ns_ = true;
}

void SandboxedProcess::SetEnvironmentVariables(
    const base::EnvironmentMap& env) {
  env_vars_ = env;
}

bool SandboxedProcess::KillProcessGroup() {
  pid_t minijail_pid = pid();
  if (minijail_pid == 0) {
    LOG(ERROR) << "Process is not running";
    return false;
  }

  // Minijail sets its process group ID equal to its PID,
  // so we can use pid() as PGID. Check that's still the case.
  pid_t pgid = getpgid(minijail_pid);
  if (pgid < 0) {
    PLOG(ERROR) << "getpgid(minijail_pid) failed";
    return false;
  }
  if (pgid != minijail_pid) {
    LOG(ERROR) << "Minijail PGID " << pgid << " is different from PID "
               << minijail_pid;
    return false;
  }

  // Attempt to kill minijail gracefully with SIGINT and then SIGTERM.
  // Note: we fall through to SIGKILLing the process group below even if this
  // succeeds to ensure all descendents have been killed.
  bool minijail_reaped = false;
  for (auto sig : {SIGINT, SIGTERM}) {
    if (kill(minijail_pid, sig) != 0) {
      // ESRCH means the process already exited.
      if (errno != ESRCH) {
        PLOG(WARNING) << "failed to kill " << minijail_pid << " with signal "
                      << sig;
      }
      break;
    }
    if (waitpid_awhile(minijail_pid)) {
      minijail_reaped = true;
      break;
    }
  }

  // kill(-pgid) kills every process with process group ID |pgid|.
  if (kill(-pgid, SIGKILL) != 0) {
    // ESRCH means the graceful exit above caught everything.
    if (errno != ESRCH) {
      PLOG(ERROR) << "kill(-pgid, SIGKILL) failed";
      return false;
    }
  }

  // If kill(2) succeeded, we release the PID.
  UpdatePid(0);

  // We only expect to reap one process, the Minijail process.
  // If the jailed process dies first, Minijail or init will reap it.
  // If the Minijail process dies first, we will reap it. The jailed process
  // will then be reaped by init.
  if (!minijail_reaped && !waitpid_awhile(minijail_pid)) {
    LOG(ERROR) << "Process " << minijail_pid << " did not terminate";
    return false;
  }

  return true;
}

}  // namespace debugd
