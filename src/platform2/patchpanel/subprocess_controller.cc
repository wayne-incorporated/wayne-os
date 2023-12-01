// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/subprocess_controller.h"

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/syslog_logging.h>
#include <shill/net/process_manager.h>

#include "patchpanel/ipc.h"
#include "patchpanel/system.h"

namespace patchpanel {
namespace {
// Maximum tries of restart.
constexpr int kMaxRestarts = 5;
// The delay of the first round of restart.
constexpr int kSubprocessRestartDelayMs = 900;
}  // namespace

SubprocessController::SubprocessController(
    System* system,
    shill::ProcessManager* process_manager,
    const base::FilePath& cmd_path,
    const std::string& fd_arg)
    : system_(system),
      process_manager_(process_manager),
      cmd_path_(cmd_path),
      fd_arg_(fd_arg) {}

SubprocessController::~SubprocessController() {
  if (pid_) {
    process_manager_->StopProcess(*pid_);
  }
}

void SubprocessController::Start() {
  if (pid_) {
    LOG(ERROR) << "The process is already running, ignore";
    return;
  }

  int control[2];

  if (system_->SocketPair(AF_UNIX, SOCK_SEQPACKET, 0, control) != 0) {
    PLOG(FATAL) << "socketpair failed";
  }

  base::ScopedFD control_fd(control[0]);
  msg_dispatcher_ = std::make_unique<MessageDispatcher<SubprocessMessage>>(
      std::move(control_fd));
  const int subprocess_fd = control[1];

  std::vector<std::string> child_argv = {fd_arg_ + "=" +
                                         std::to_string(subprocess_fd)};
  const std::vector<std::pair<int, int>> fds_to_bind = {
      {subprocess_fd, subprocess_fd}};

  const auto pid = process_manager_->StartProcess(
      FROM_HERE, cmd_path_, child_argv, /*environment=*/{}, fds_to_bind, true,
      base::BindOnce(&SubprocessController::OnProcessExitedUnexpectedly,
                     weak_factory_.GetWeakPtr()));
  if (pid != shill::ProcessManager::kInvalidPID) {
    pid_ = pid;
  } else {
    LOG(ERROR) << "Failed to start the subprocess: " << fd_arg_;
  }
}

void SubprocessController::OnProcessExitedUnexpectedly(int exit_status) {
  const auto delay = base::Milliseconds(kSubprocessRestartDelayMs << restarts_);
  LOG(ERROR) << "Subprocess: " << fd_arg_ << " (pid = " << *pid_
             << " ) exited unexpectedly, status: " << exit_status
             << ", attempting to restart after " << delay;

  pid_ = std::nullopt;

  ++restarts_;
  if (restarts_ > kMaxRestarts) {
    LOG(ERROR) << "Subprocess: " << fd_arg_
               << " exceeded maximum number of restarts";
    return;
  }

  // Restart the subprocess with exponential backoff delay.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&SubprocessController::Start, weak_factory_.GetWeakPtr()),
      delay);
}

void SubprocessController::SendControlMessage(
    const ControlMessage& proto) const {
  if (!msg_dispatcher_) {
    return;
  }
  SubprocessMessage msg;
  *msg.mutable_control_message() = proto;
  msg_dispatcher_->SendMessage(msg);
}

void SubprocessController::Listen() {
  if (!msg_dispatcher_) {
    return;
  }
  msg_dispatcher_->RegisterMessageHandler(base::BindRepeating(
      &SubprocessController::OnMessage, weak_factory_.GetWeakPtr()));
}

void SubprocessController::RegisterFeedbackMessageHandler(
    base::RepeatingCallback<void(const FeedbackMessage&)> handler) {
  feedback_handler_ = std::move(handler);
}

void SubprocessController::OnMessage(const SubprocessMessage& msg) {
  if (msg.has_feedback_message() && !feedback_handler_.is_null()) {
    feedback_handler_.Run(msg.feedback_message());
  }
}

}  // namespace patchpanel
