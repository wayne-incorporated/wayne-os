// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <bits/types/siginfo_t.h>

#include <memory>
#include <utility>

#include <base/posix/eintr_wrapper.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "diagnostics/cros_healthd/executor/utils/process_control.h"

namespace diagnostics {

ProcessControl::ProcessControl(std::unique_ptr<SandboxedProcess> process,
                               brillo::ProcessReaper* process_reaper)
    : process_(std::move(process)), process_reaper_(process_reaper) {
  CHECK(!process_->pid()) << "The process has already started.";
}

ProcessControl::~ProcessControl() = default;

void ProcessControl::RedirectOutputToMemory(bool combine_stdout_and_stderr) {
  process_->RedirectOutputToMemory(combine_stdout_and_stderr);
}

void ProcessControl::StartAndWait() {
  process_->Start();
  process_reaper_->WatchForChild(
      FROM_HERE, process_->pid(),
      base::BindOnce(&ProcessControl::SetProcessFinished,
                     weak_factory_.GetWeakPtr()));
}

void ProcessControl::SetProcessFinished(const siginfo_t& siginfo) {
  return_code_ = siginfo.si_status;
  process_->Release();

  std::vector<GetReturnCodeCallback> return_code_callbacks;
  return_code_callbacks.swap(get_return_code_callback_queue_);
  for (size_t i = 0; i < return_code_callbacks.size(); ++i) {
    std::move(return_code_callbacks[i]).Run(return_code_.value());
  }
}

void ProcessControl::GetStdout(GetStdoutCallback callback) {
  std::move(callback).Run(GetMojoScopedHandle(STDOUT_FILENO));
}

void ProcessControl::GetStderr(GetStderrCallback callback) {
  std::move(callback).Run(GetMojoScopedHandle(STDERR_FILENO));
}

void ProcessControl::GetReturnCode(GetReturnCodeCallback callback) {
  if (!return_code_.has_value()) {
    get_return_code_callback_queue_.push_back(std::move(callback));
    return;
  }
  std::move(callback).Run(return_code_.value());
}

void ProcessControl::Kill() {
  // If the process is already dead, no need to kill again.
  if (return_code_.has_value()) {
    return;
  }
  process_reaper_->ForgetChild(process_->pid());
  return_code_ = process_->KillAndWaitSandboxProcess();
  if (return_code_ == -1) {
    LOG(ERROR) << "Unsuccessful call to kill.";
  }

  std::vector<GetReturnCodeCallback> return_code_callbacks;
  return_code_callbacks.swap(get_return_code_callback_queue_);
  for (size_t i = 0; i < return_code_callbacks.size(); ++i) {
    std::move(return_code_callbacks[i]).Run(return_code_.value());
  }
}

mojo::ScopedHandle ProcessControl::GetMojoScopedHandle(int file_no) {
  base::ScopedPlatformFile other_fd(
      HANDLE_EINTR(dup(process_->GetOutputFd(file_no))));
  return mojo::WrapPlatformFile(std::move(other_fd));
}

}  // namespace diagnostics
