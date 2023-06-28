// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/child_exit_dispatcher.h"

#include <algorithm>

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <base/bind.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <brillo/asynchronous_signal_handler.h>

#include "login_manager/child_exit_handler.h"
#include "login_manager/child_job.h"

namespace login_manager {

ChildExitDispatcher::ChildExitDispatcher(
    brillo::AsynchronousSignalHandler* signal_handler,
    const std::vector<ChildExitHandler*>& handlers)
    : signal_handler_(signal_handler), handlers_(handlers) {
  signal_handler_->RegisterHandler(
      SIGCHLD,
      base::Bind(&ChildExitDispatcher::OnSigChld, base::Unretained(this)));
}

ChildExitDispatcher::~ChildExitDispatcher() {
  signal_handler_->UnregisterHandler(SIGCHLD);
}

bool ChildExitDispatcher::OnSigChld(const struct signalfd_siginfo& sig_info) {
  DCHECK_EQ(sig_info.ssi_signo, SIGCHLD) << "Wrong signal!";
  if (sig_info.ssi_code == CLD_STOPPED || sig_info.ssi_code == CLD_CONTINUED) {
    return false;
  }

  auto ptr = weak_factory_.GetWeakPtr();

  siginfo_t info;
  // Reap all terminated children.
  while (true) {
    memset(&info, 0, sizeof(info));
    int result = waitid(P_ALL, 0, &info, WEXITED | WNOHANG);
    if (result != 0) {
      if (errno != ECHILD)
        PLOG(FATAL) << "waitid failed";
      break;
    }
    if (info.si_pid == 0)
      break;
    // Before calling Dispatch(), check if this class is still alive.
    // If not, do not call Dispatch() to avoid use-after-free.
    // The situation happens when this instance is destroyed in HandleExit().
    // Note that this still consumes all pending children even in the case
    // for consistent behavior.
    // TODO(crbug.com/1053782): Migrate to libbrillo library.
    if (ptr)
      Dispatch(info);
  }
  // Continue listening to SIGCHLD
  return false;
}

void ChildExitDispatcher::Dispatch(const siginfo_t& info) {
  if (info.si_code == CLD_EXITED) {
    CHECK_NE(info.si_status, ChildJobInterface::kCantSetUid) << info.si_pid;
    CHECK_NE(info.si_status, ChildJobInterface::kCantSetEnv) << info.si_pid;
    CHECK_NE(info.si_status, ChildJobInterface::kCantExec) << info.si_pid;
  }

  for (auto* handler : handlers_) {
    if (handler->HandleExit(info)) {
      return;
    }
  }

  // No handler handled the exit.
  VLOG(1) << "Unmanaged process " << info.si_pid << " exited with "
          << ChildExitHandler::GetExitDescription(info);
}

}  // namespace login_manager
