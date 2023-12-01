// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/process_manager.h"

#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>

namespace shill {

namespace {

base::LazyInstance<ProcessManager>::DestructorAtExit g_process_manager =
    LAZY_INSTANCE_INITIALIZER;

static const int kWaitpidPollTimesForSIGTERM = 10;
static const int kWaitpidPollTimesForSIGKILL = 8;
static const unsigned int kWaitpidPollIntervalUpperBoundMilliseconds = 2000;
static const unsigned int kWaitpidPollInitialIntervalMilliseconds = 4;

// The maximum size we keep for the stdout of a process.
static constexpr int kMaxStdoutBufferSize = 32 * 1024;

bool SetupChild(const std::map<std::string, std::string>& env,
                bool terminate_with_parent) {
  // Setup environment variables.
  clearenv();
  for (const auto& key_value : env) {
    setenv(key_value.first.c_str(), key_value.second.c_str(), 0);
  }
  if (terminate_with_parent) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
  }
  return true;
}

}  // namespace

ProcessManager::ProcessManager() = default;

ProcessManager::~ProcessManager() = default;

// static
ProcessManager* ProcessManager::GetInstance() {
  return g_process_manager.Pointer();
}

void ProcessManager::Init() {
  VLOG(2) << __func__;
  CHECK(!async_signal_handler_);
  async_signal_handler_.reset(new brillo::AsynchronousSignalHandler());
  async_signal_handler_->Init();
  process_reaper_.Register(async_signal_handler_.get());
  minijail_ = brillo::Minijail::GetInstance();
}

void ProcessManager::Stop() {
  VLOG(2) << __func__;
  CHECK(async_signal_handler_);
  process_reaper_.Unregister();
  async_signal_handler_.reset();

  // Kill the pending termination processes (which we have already sent SIGTERM
  // to). Note that currently the process started by minijail will not be killed
  // automatically when shill quits, so we need to do this manually. See
  // b/261666421 for an issue in the test which caused by this.
  for (const auto& [pid, callback] : pending_termination_processes_) {
    LOG(WARNING) << __func__ << ": send SIGKILL to " << pid;
    bool not_used;
    // Error will be logged in KillProcess().
    KillProcess(pid, SIGKILL, &not_used);
  }
  pending_termination_processes_.clear();
}

pid_t ProcessManager::StartProcess(
    const base::Location& spawn_source,
    const base::FilePath& program,
    const std::vector<std::string>& arguments,
    const std::map<std::string, std::string>& environment,
    const std::vector<std::pair<int, int>>& fds_to_bind,
    bool terminate_with_parent,
    ExitCallback exit_callback) {
  VLOG(2) << __func__ << "(" << program.value() << ")";

  // Setup/create child process.
  std::unique_ptr<brillo::Process> process(new brillo::ProcessImpl());
  process->AddArg(program.value());
  for (const auto& option : arguments) {
    process->AddArg(option);
  }
  for (const auto& pair : fds_to_bind) {
    process->BindFd(pair.first, pair.second);
  }
  // Important to close unused fds. See crbug.com/531655 and crbug.com/911234.
  process->SetCloseUnusedFileDescriptors(true);
  process->SetPreExecCallback(
      base::BindOnce(&SetupChild, environment, terminate_with_parent));
  if (!process->Start()) {
    LOG(ERROR) << "Failed to start child process for " << program.value();
    return kInvalidPID;
  }

  // Setup watcher for the child process.
  pid_t pid = process->pid();
  CHECK(process_reaper_.WatchForChild(
      spawn_source, pid,
      base::BindOnce(&ProcessManager::OnProcessExited,
                     weak_factory_.GetWeakPtr(), pid)));

  // Release ownership of the child process from the |process| object, so that
  // child process will not get killed on destruction of |process| object.
  process->Release();

  watched_processes_[pid].exit_callback = std::move(exit_callback);
  return pid;
}

pid_t ProcessManager::StartProcessInMinijailWithPipes(
    const base::Location& spawn_source,
    const base::FilePath& program,
    const std::vector<std::string>& arguments,
    const std::map<std::string, std::string>& environment,
    const MinijailOptions& minijail_options,
    ExitCallback exit_callback,
    struct std_file_descriptors std_fds) {
  pid_t pid = StartProcessInMinijailWithPipesInternal(
      spawn_source, program, arguments, environment, minijail_options, std_fds);
  if (pid == kInvalidPID) {
    return pid;
  }
  watched_processes_[pid].exit_callback = std::move(exit_callback);
  return pid;
}

pid_t ProcessManager::StartProcessInMinijailWithStdout(
    const base::Location& spawn_source,
    const base::FilePath& program,
    const std::vector<std::string>& arguments,
    const std::map<std::string, std::string>& environment,
    const MinijailOptions& minijail_options,
    ExitWithStdoutCallback exit_callback) {
  int stdout_fd;
  pid_t pid = StartProcessInMinijailWithPipesInternal(
      spawn_source, program, arguments, environment, minijail_options,
      {.stdout_fd = &stdout_fd});
  if (pid == kInvalidPID) {
    return pid;
  }
  auto& watched_process = watched_processes_[pid];
  watched_process.exit_with_stdout_callback = std::move(exit_callback);
  watched_process.stdout_fd.reset(stdout_fd);
  watched_process.stdout_watcher = base::FileDescriptorWatcher::WatchReadable(
      stdout_fd, base::BindRepeating(&ProcessManager::OnProcessStdoutReadable,
                                     weak_factory_.GetWeakPtr(), pid));
  return pid;
}

bool ProcessManager::StopProcess(pid_t pid) {
  VLOG(2) << __func__ << "(" << pid << ")";

  if (pending_termination_processes_.find(pid) !=
      pending_termination_processes_.end()) {
    LOG(ERROR) << "Process " << pid << " already being stopped.";
    return false;
  }

  if (watched_processes_.find(pid) == watched_processes_.end()) {
    LOG(ERROR) << "Process " << pid << " not being watched";
    return false;
  }
  // Caller not interested in watching this process anymore, since the
  // process termination is initiated by the caller.
  watched_processes_.erase(pid);

  // Attempt to send SIGTERM signal first.
  return TerminateProcess(pid, false);
}

bool ProcessManager::StopProcessAndBlock(pid_t pid) {
  VLOG(2) << __func__ << "(" << pid << ")";

  auto terminated_process = pending_termination_processes_.find(pid);

  if (terminated_process != pending_termination_processes_.end()) {
    LOG(INFO) << "Process " << pid << " already being stopped.";
    terminated_process->second->Cancel();
    pending_termination_processes_.erase(terminated_process);
  } else {
    if (watched_processes_.find(pid) == watched_processes_.end()) {
      LOG(ERROR) << "Process " << pid << " not being watched";
      return false;
    }
    // Caller not interested in watching this process anymore, since the
    // process termination is initiated by the caller.
    watched_processes_.erase(pid);
  }

  // We are no longer interested in tracking the exit of this process.
  // Also, we will hopefully reap this process ourselves, so remove any
  // record of this pid from process_reaper_.
  process_reaper_.ForgetChild(pid);

  // Try SIGTERM firstly.
  // Send SIGKILL signal if SIGTERM was not handled in a timely manner.
  if (KillProcessWithTimeout(pid, false) || KillProcessWithTimeout(pid, true)) {
    return true;
  }

  // In case of killing failure.
  LOG(ERROR) << "Timeout waiting for process " << pid << " to be killed.";

  return false;
}

bool ProcessManager::KillProcessWithTimeout(pid_t pid, bool kill_signal) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  bool killed = false;
  if (KillProcess(pid, kill_signal ? SIGKILL : SIGTERM, &killed)) {
    if (killed) {
      return true;
    }

    int poll_times =
        kill_signal ? kWaitpidPollTimesForSIGKILL : kWaitpidPollTimesForSIGTERM;

    if (WaitpidWithTimeout(pid, kWaitpidPollInitialIntervalMilliseconds,
                           kWaitpidPollIntervalUpperBoundMilliseconds,
                           poll_times)) {
      return true;
    }
  }
  return false;
}

bool ProcessManager::KillProcess(pid_t pid, int signal, bool* killed) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  if (kill(pid, signal) < 0) {
    if (errno == ESRCH) {
      VLOG(2) << "Process " << pid << " has exited.";
      *killed = true;
      return true;
    }
    PLOG(ERROR) << "Failed to send " << signal << "signal to process " << pid;
    return false;
  }
  return true;
}

bool ProcessManager::WaitpidWithTimeout(pid_t pid,
                                        unsigned int sleep_ms,
                                        unsigned int upper_bound_ms,
                                        int tries) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  while (tries-- > 0) {
    if (waitpid(pid, nullptr, WNOHANG) == pid) {
      return true;
    }
    usleep(sleep_ms * 1000);
    if (2 * sleep_ms < upper_bound_ms) {
      sleep_ms *= 2;
    }
  }
  return false;
}

bool ProcessManager::UpdateExitCallback(pid_t pid, ExitCallback new_callback) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  const auto process_entry = watched_processes_.find(pid);
  if (process_entry == watched_processes_.end()) {
    LOG(ERROR) << "Process " << pid << " not being watched";
    return false;
  }

  process_entry->second.exit_callback = std::move(new_callback);
  return true;
}

pid_t ProcessManager::StartProcessInMinijailWithPipesInternal(
    const base::Location& spawn_source,
    const base::FilePath& program,
    const std::vector<std::string>& arguments,
    const std::map<std::string, std::string>& environment,
    const MinijailOptions& minijail_options,
    struct std_file_descriptors std_fds) {
  VLOG(2) << __func__ << "(" << program.value() << ")";

  std::vector<char*> args;
  args.push_back(const_cast<char*>(program.value().c_str()));
  for (const auto& arg : arguments) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  args.push_back(nullptr);

  std::vector<std::string> env_strings;
  for (const auto& var : environment) {
    env_strings.push_back(
        base::StringPrintf("%s=%s", var.first.c_str(), var.second.c_str()));
  }
  std::vector<char*> env;
  for (const auto& str : env_strings) {
    env.push_back(const_cast<char*>(str.c_str()));
  }
  env.push_back(nullptr);

  struct minijail* jail = minijail_->New();

  if (!minijail_->DropRoot(jail, minijail_options.user.c_str(),
                           minijail_options.group.c_str())) {
    LOG(ERROR) << "Minijail failed to drop root privileges?";
    return kInvalidPID;
  }

  if (minijail_options.inherit_supplementary_groups) {
    minijail_inherit_usergroups(jail);
  }

  minijail_->UseCapabilities(jail, minijail_options.capmask);
  minijail_->ResetSignalMask(jail);
  minijail_->PreserveFd(jail, STDIN_FILENO, STDIN_FILENO);
  minijail_->PreserveFd(jail, STDOUT_FILENO, STDOUT_FILENO);
  minijail_->PreserveFd(jail, STDERR_FILENO, STDERR_FILENO);
  for (int fd : minijail_options.preserved_nonstd_fds) {
    minijail_->PreserveFd(jail, fd, fd);
  }
  // Important to close non-standard fds. See b/286322349, crbug.com/531655,
  // crbug.com/911234, crbug.com/914444.
  minijail_->CloseOpenFds(jail);

  if (minijail_options.rlimit_as_soft.has_value()) {
    minijail_rlimit(jail, RLIMIT_AS, minijail_options.rlimit_as_soft.value(),
                    RLIM_INFINITY);
  }

  pid_t pid;
  if (!minijail_->RunEnvPipesAndDestroy(jail, args, env, &pid, std_fds.stdin_fd,
                                        std_fds.stdout_fd, std_fds.stderr_fd)) {
    LOG(ERROR) << "Unable to spawn " << program.value() << " in a jail.";
    return kInvalidPID;
  }

  CHECK(process_reaper_.WatchForChild(
      spawn_source, pid,
      base::BindOnce(&ProcessManager::OnProcessExited,
                     weak_factory_.GetWeakPtr(), pid)));

  return pid;
}

void ProcessManager::OnProcessStdoutReadable(pid_t pid) {
  auto watched_process_it = watched_processes_.find(pid);
  if (watched_process_it == watched_processes_.end()) {
    LOG(ERROR) << __func__ << " called but process " << pid
               << " is not being tracked.";
    return;
  }

  int fd = watched_process_it->second.stdout_fd.get();

  // PIPE_BUF is defined in the kernel, which specifies the maximum size of a
  // atomic write to a pipe. The value is 4KB in Linux.
  constexpr int kBufferSize = PIPE_BUF;
  char buffer[kBufferSize];
  while (1) {
    ssize_t ret = HANDLE_EINTR(read(fd, buffer, kBufferSize));
    if (ret == -1 && errno == EAGAIN) {
      // The pipe is empty now. Waits for more data.
      return;
    } else if (ret == 0 || ret == -1) {
      // 0 means we got an EOF, -1 means we got a real error. In both cases, the
      // read is done and we should check if the callback should be invoked.
      if (ret == -1) {
        PLOG(ERROR) << "Failed to read stdout for process " << pid;
      }
      watched_process_it->second.stdout_watcher = nullptr;
      watched_process_it->second.stdout_fd.reset();
      CheckProcessExitStateAndNotify(pid);
      return;
    } else {
      // We got some data.
      watched_process_it->second.stdout_str.append(buffer, ret);
      if (watched_process_it->second.stdout_str.size() > kMaxStdoutBufferSize) {
        watched_process_it->second.stdout_str.resize(kMaxStdoutBufferSize);
      }
    }
  }
}

void ProcessManager::OnProcessExited(pid_t pid, const siginfo_t& info) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  // Invoke the exit callback if the process is being watched.
  auto watched_process = watched_processes_.find(pid);
  if (watched_process != watched_processes_.end()) {
    watched_process->second.exit_status = info.si_status;
    CheckProcessExitStateAndNotify(pid);
    return;
  }

  // Process terminated by us, cancel timeout handler.
  auto terminated_process = pending_termination_processes_.find(pid);
  if (terminated_process != pending_termination_processes_.end()) {
    terminated_process->second->Cancel();
    pending_termination_processes_.erase(terminated_process);
    return;
  }

  NOTREACHED() << "Unknown process " << pid << " status " << info.si_status;
}

void ProcessManager::CheckProcessExitStateAndNotify(pid_t pid) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  auto watched_process_it = watched_processes_.find(pid);
  CHECK(watched_process_it != watched_processes_.end());

  const auto& process = watched_process_it->second;

  if (!process.exit_callback.is_null()) {
    if (!process.exit_status.has_value()) {
      LOG(DFATAL) << __func__ << " called but |exit_status| is empty";
      return;
    }
    ExitCallback callback = std::move(watched_process_it->second.exit_callback);
    std::move(callback).Run(process.exit_status.value());
    watched_processes_.erase(watched_process_it);
    return;
  }

  CHECK(!process.exit_with_stdout_callback.is_null());
  if (process.exit_status.has_value() && !process.stdout_fd.is_valid()) {
    ExitWithStdoutCallback callback =
        std::move(watched_process_it->second.exit_with_stdout_callback);
    std::move(callback).Run(process.exit_status.value(), process.stdout_str);
    watched_processes_.erase(watched_process_it);
  }
}

void ProcessManager::ProcessTerminationTimeoutHandler(pid_t pid,
                                                      bool kill_signal) {
  VLOG(2) << __func__ << "(pid: " << pid << ")";

  CHECK(pending_termination_processes_.find(pid) !=
        pending_termination_processes_.end());
  pending_termination_processes_.erase(pid);
  // Process still not killed after SIGKILL signal.
  if (kill_signal) {
    LOG(ERROR) << "Timeout waiting for process " << pid << " to be killed.";
    return;
  }

  // Retry using SIGKILL signal.
  TerminateProcess(pid, true);
}

bool ProcessManager::TerminateProcess(pid_t pid, bool kill_signal) {
  VLOG(2) << __func__ << "(pid: " << pid << ", "
          << "use_sigkill: " << kill_signal << ")";

  int signal = (kill_signal) ? SIGKILL : SIGTERM;
  bool killed = false;
  if (!KillProcess(pid, signal, &killed)) {
    return false;
  }
  if (killed) {
    return true;
  }
  auto termination_callback = std::make_unique<TerminationTimeoutCallback>(
      base::BindOnce(&ProcessManager::ProcessTerminationTimeoutHandler,
                     weak_factory_.GetWeakPtr(), pid, kill_signal));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, termination_callback->callback(), kTerminationTimeout);
  pending_termination_processes_[pid] = std::move(termination_callback);
  return true;
}

std::optional<bool> ProcessManager::IsTerminating(
    const base::FilePath& pid_path) {
  if (!base::PathExists(pid_path)) {
    return false;
  }
  std::string filepid;
  if (!base::ReadFileToString(pid_path, &filepid)) {
    LOG(ERROR) << "Failed to read the pid file";
    return std::nullopt;
  }

  if (!base::TrimString(filepid, "\n", &filepid)) {
    LOG(ERROR) << "Failed to get the pid: current filepid value is " << filepid;
    return std::nullopt;
  }
  pid_t pid;
  if (!base::StringToInt(filepid, &pid)) {
    LOG(ERROR) << "Failed to change type of the pid value from string to int: "
                  "current filepid value is "
               << filepid;
    return std::nullopt;
  }
  return pending_termination_processes_.find(pid) !=
         pending_termination_processes_.end();
}

}  // namespace shill
