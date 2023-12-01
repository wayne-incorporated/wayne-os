// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/process_manager.h"

#include <unistd.h>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

using std::string;
using std::vector;

namespace {

bool LaunchProcess(const vector<string>& cmd,
                   int output_pipe,
                   brillo::Process* proc) {
  for (const string& arg : cmd)
    proc->AddArg(arg);

  proc->RedirectUsingPipe(output_pipe, false);
  proc->SetCloseUnusedFileDescriptors(true);
  proc->RedirectUsingPipe(STDOUT_FILENO, false);
  return proc->Start();
}

}  // namespace

std::unique_ptr<brillo::Process> ProcessManager::CreateProcess(
    const vector<string>& cmd,
    const ProcessManagerInterface::IORedirection& io_redirection) {
  std::unique_ptr<brillo::Process> process(new brillo::ProcessImpl);
  for (const auto& arg : cmd)
    process->AddArg(arg);
  if (!io_redirection.input.empty())
    process->RedirectInput(io_redirection.input);
  if (!io_redirection.output.empty())
    process->RedirectOutput(io_redirection.output);
  return process;
}

int ProcessManager::RunCommand(
    const vector<string>& cmd,
    const ProcessManagerInterface::IORedirection& io_redirection) {
  auto process = CreateProcess(cmd, io_redirection);
  return process->Run();
}

bool ProcessManager::RunBackgroundCommand(
    const vector<string>& cmd,
    const ProcessManagerInterface::IORedirection& io_redirection,
    pid_t* pid) {
  auto process = CreateProcess(cmd, io_redirection);
  if (!process->Start())
    return false;
  *pid = process->pid();
  // Need to release the process so it's not destructed at return.
  process->Release();
  return true;
}

bool ProcessManager::RunCommandWithOutput(const vector<string>& cmd,
                                          int* return_code,
                                          string* stdout_out,
                                          string* stderr_out) {
  brillo::ProcessImpl proc;
  if (!LaunchProcess(cmd, STDERR_FILENO, &proc)) {
    LOG(ERROR) << "Failed to launch subprocess";
    return false;
  }

  // Read from both stdout and stderr individually.
  int stdout_fd = proc.GetPipe(STDOUT_FILENO);
  int stderr_fd = proc.GetPipe(STDERR_FILENO);
  vector<char> buffer(32 * 1024);
  bool stdout_closed = false, stderr_closed = false;
  while (!stdout_closed || !stderr_closed) {
    if (!stdout_closed) {
      int rc = HANDLE_EINTR(read(stdout_fd, buffer.data(), buffer.size()));
      if (rc <= 0) {
        stdout_closed = true;
        if (rc < 0)
          PLOG(ERROR) << "Reading from child's stdout";
      } else if (stdout_out != nullptr) {
        stdout_out->append(buffer.data(), rc);
      }
    }

    if (!stderr_closed) {
      int rc = HANDLE_EINTR(read(stderr_fd, buffer.data(), buffer.size()));
      if (rc <= 0) {
        stderr_closed = true;
        if (rc < 0)
          PLOG(ERROR) << "Reading from child's stderr";
      } else if (stderr_out != nullptr) {
        stderr_out->append(buffer.data(), rc);
      }
    }
  }

  // At this point, the subprocess already closed the output, so we only need to
  // wait for it to finish.
  int proc_return_code = proc.Wait();
  if (return_code)
    *return_code = proc_return_code;
  return proc_return_code != brillo::Process::kErrorExitStatus;
}
