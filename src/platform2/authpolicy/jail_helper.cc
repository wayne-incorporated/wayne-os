// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/jail_helper.h"

#include <memory>

#include "authpolicy/platform_helper.h"
#include "authpolicy/process_executor.h"
#include "bindings/authpolicy_containers.pb.h"

#include <base/check.h>

namespace authpolicy {

class AuthPolicyFlags;
class PathService;

JailHelper::JailHelper(const PathService* path_service,
                       const protos::DebugFlags* flags,
                       Anonymizer* anonymizer)
    : paths_(path_service), flags_(flags), anonymizer_(anonymizer) {}

bool JailHelper::SetupJailAndRun(ProcessExecutor* cmd,
                                 Path seccomp_path_key,
                                 TimerType timer_type) const {
  // Limit the system calls that the process can do.
  DCHECK(cmd);
  if (!flags_->disable_seccomp()) {
    cmd->LogSeccompFilterFailures(flags_->log_seccomp());
    cmd->SetSeccompFilter(paths_->Get(seccomp_path_key));
  }

  // Required since we don't have the caps to wipe supplementary groups.
  cmd->KeepSupplementaryGroups(true);

  // Allows us to drop setgroups, setresgid and setresuid from seccomp filters.
  cmd->SetNoNewPrivs(true);

  // Set up logging.
  cmd->LogCommand(flags_->log_commands());
  cmd->LogOutput(flags_->log_command_output());
  cmd->LogOutputOnError(flags_->log_command_output_on_error());
  cmd->SetAnonymizer(anonymizer_);

  // Execute as authpolicyd exec user. Don't use minijail to switch user. This
  // would force us to run without preload library since saved UIDs are wiped by
  // execve and the executed code wouldn't be able to switch user. Running with
  // preload library has two main advantages:
  //   1) Tighter seccomp filters, no need to allow execve and others.
  //   2) Ability to log seccomp filter failures. Without this, it is hard to
  //      know which syscall has to be added to the filter policy file.
  auto timer = timer_type != TIMER_NONE
                   ? std::make_unique<ScopedTimerReporter>(timer_type)
                   : nullptr;
  ScopedSwitchToSavedUid switch_scope;
  return cmd->Execute();
}

}  // namespace authpolicy
