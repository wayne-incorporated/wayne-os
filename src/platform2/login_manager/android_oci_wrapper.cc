// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/android_oci_wrapper.h"

#include <signal.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "login_manager/system_utils.h"

namespace login_manager {

constexpr char AndroidOciWrapper::kContainerPath[];
constexpr char AndroidOciWrapper::kContainerId[];
constexpr char AndroidOciWrapper::kContainerPidName[];
constexpr char AndroidOciWrapper::kRunOciPath[];
constexpr char AndroidOciWrapper::kRunOciLogging[];
constexpr char AndroidOciWrapper::kRunOciStartCommand[];
constexpr char AndroidOciWrapper::kRunOciKillCommand[];
constexpr char AndroidOciWrapper::kRunOciKillSignal[];
constexpr char AndroidOciWrapper::kRunOciDestroyCommand[];
constexpr char AndroidOciWrapper::kRunOciConfigPath[];
constexpr char AndroidOciWrapper::kProcFdPath[];

AndroidOciWrapper::AndroidOciWrapper(SystemUtils* system_utils,
                                     const base::FilePath& containers_directory)
    : system_utils_(system_utils), containers_directory_(containers_directory) {
  DCHECK(system_utils_);
  DCHECK(!containers_directory_.empty());
}

AndroidOciWrapper::~AndroidOciWrapper() = default;

bool AndroidOciWrapper::HandleExit(const siginfo_t& status) {
  if (!container_pid_ || status.si_pid != container_pid_)
    return false;

  LOG(INFO) << "Android container " << status.si_pid << " exited with "
            << GetExitDescription(status);

  stateful_mode_ = StatefulMode::STATELESS;
  CleanUpContainer();
  return true;
}

void AndroidOciWrapper::RequestJobExit(ArcContainerStopReason reason) {
  if (!container_pid_)
    return;

  exit_reason_ = reason;

  if (stateful_mode_ == StatefulMode::STATEFUL) {
    if (RequestTermination())
      return;
  }

  std::vector<std::string> argv = {kRunOciPath, kRunOciLogging,
                                   kRunOciKillSignal, kRunOciKillCommand,
                                   kContainerId};

  int exit_code = -1;
  LOG(INFO) << "Forcefully shutting down container " << container_pid_;
  if (!system_utils_->LaunchAndWait(argv, &exit_code)) {
    PLOG(ERROR) << "Failed to run run_oci";
    return;
  }

  if (exit_code) {
    PLOG(ERROR) << "run_oci failed to forcefully shut down container \""
                << kContainerId << "\"";
  }
}

void AndroidOciWrapper::EnsureJobExit(base::TimeDelta timeout) {
  pid_t pid;
  if (GetContainerPID(&pid) && !system_utils_->ProcessIsGone(pid, timeout)) {
    LOG(INFO) << "Killing container " << pid;
    if (system_utils_->kill(pid, -1, SIGKILL))
      PLOG(ERROR) << "Failed to kill container " << pid;

    // Reap container process here. run_oci uses kill(2) to detect whether the
    // process is gone, so reap it here to avoid kernel telling run_oci that
    // the process is still there. We killed |pid| just now so we won't need
    // more than 1s to reap it, but I'll give it 5s because this failure is not
    // recoverable until next reboot.
    if (!system_utils_->ProcessIsGone(pid, base::TimeDelta::FromSeconds(5)))
      LOG(ERROR) << "Container process " << pid << " is still here";
  }

  CleanUpContainer();
}

bool AndroidOciWrapper::StartContainer(const std::vector<std::string>& env,
                                       const ExitCallback& exit_callback) {
  pid_t pid = system_utils_->fork();

  if (pid < 0) {
    PLOG(ERROR) << "Failed to fork a new process for run_oci";
    return false;
  }

  // This is the child process.
  if (pid == 0) {
    ExecuteRunOciToStartContainer(env);

    // Child process should never come down to this point, but we can't mimic
    // this behavior in unit tests, so add a return here to make unit tests
    // pass.
    return false;
  }

  // This is the parent process. The child process can't reach this point.
  LOG(INFO) << "run_oci PID: " << pid;

  int status = -1;
  pid_t result =
      system_utils_->Wait(pid, base::TimeDelta::FromSeconds(90), &status);
  if (result != pid) {
    if (result)
      PLOG(ERROR) << "Failed to wait on run_oci exit";
    else
      LOG(ERROR) << "Timed out to wait on run_oci exit";

    // We assume libcontainer won't create a new process group for init process,
    // so we can use run_oci's PID as the PGID to kill all processes in the
    // container because we created a session in run_oci process.
    KillProcessGroup(pid);

    // Since we've killed run_oci asynchronously, run_oci might have died
    // without cleaning up the container directory. Run run_oci again to make
    // sure the directory is gone.
    std::vector<std::string> argv = {kRunOciPath, kRunOciLogging,
                                     kRunOciConfigPath, kRunOciDestroyCommand,
                                     kContainerId};
    int exit_code = -1;
    if (!system_utils_->LaunchAndWait(argv, &exit_code)) {
      PLOG(ERROR) << "Failed to run run_oci";
    } else if (exit_code) {
      LOG(ERROR) << "run_oci failed to clean up resources for \""
                 << kContainerId << "\"";
    }

    return false;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status)) {
    LOG(ERROR) << "run_oci failed to launch Android container. WIFEXITED: "
               << WIFEXITED(status) << " WEXITSTATUS: " << WEXITSTATUS(status);
    return false;
  }

  base::FilePath container_pid_path =
      base::FilePath(ContainerManagerInterface::kContainerRunPath)
          .Append(kContainerId)
          .Append(kContainerPidName);

  std::string pid_str;
  if (!system_utils_->ReadFileToString(container_pid_path, &pid_str)) {
    PLOG(ERROR) << "Failed to read container pid file";
    KillProcessGroup(pid);
    return false;
  }
  if (!base::StringToInt(base::TrimWhitespaceASCII(pid_str, base::TRIM_ALL),
                         &container_pid_)) {
    LOG(ERROR) << "Failed to convert \"" << pid_str << "\" to pid";
    KillProcessGroup(pid);
    return false;
  }

  LOG(INFO) << "Container PID: " << container_pid_;

  exit_callback_ = exit_callback;
  // Set CRASH initially. So if ARC is stopped without RequestJobExit() call,
  // it will be handled as CRASH.
  exit_reason_ = ArcContainerStopReason::CRASH;

  return true;
}

bool AndroidOciWrapper::GetContainerPID(pid_t* pid_out) const {
  if (!container_pid_)
    return false;

  *pid_out = container_pid_;
  return true;
}

StatefulMode AndroidOciWrapper::GetStatefulMode() const {
  return stateful_mode_;
}

void AndroidOciWrapper::SetStatefulMode(StatefulMode mode) {
  stateful_mode_ = mode;
}

void AndroidOciWrapper::ExecuteRunOciToStartContainer(
    const std::vector<std::string>& env) {
  // Clear signal mask.
  if (!system_utils_->ChangeBlockedSignals(SIG_SETMASK, std::vector<int>()))
    PLOG(FATAL) << "Failed to clear blocked signals";

  base::FilePath container_absolute_path =
      containers_directory_.Append(kContainerPath);
  if (system_utils_->chdir(container_absolute_path))
    PLOG(FATAL) << "Failed to change directory";

  // Close all FDs inherited from session manager.
  if (!CloseOpenedFiles())
    PLOG(FATAL) << "Failed to close all fds";

  if (system_utils_->setsid() < 0)
    PLOG(FATAL) << "Failed to create a new session";

  constexpr const char* const args[] = {kRunOciPath,       kRunOciLogging,
                                        kRunOciConfigPath, kRunOciStartCommand,
                                        kContainerId,      nullptr};

  // Increase oom_score_adj to -100.
  // Android system processes should be killable in case they exhibit memory
  // leaks.  Without this change, they would have an oom_score_adj of -1000,
  // making them unkillable. Android application processes will later have their
  // oom_score_adj furthur increased. This value was chosen so that as long as a
  // process is using less than 10% of memory, it will have an oom badness score
  // of 1 (the lowest possible not counting unkillable processes). The threshold
  // of 10% is an arbitrary line in the sand.
  if (!system_utils_->WriteStringToFile(
          base::FilePath("/proc/self/oom_score_adj"), "-100")) {
    PLOG(FATAL) << "Failed to set oom_score_adj";
  }

  std::vector<const char*> cstr_env;
  cstr_env.reserve(env.size() + 1);
  for (const std::string& keyval : env)
    cstr_env.emplace_back(keyval.c_str());
  cstr_env.emplace_back(nullptr);
  if (system_utils_->execve(base::FilePath(kRunOciPath), args, cstr_env.data()))
    PLOG(FATAL) << "Failed to run run_oci";
}

bool AndroidOciWrapper::RequestTermination() {
  LOG(INFO) << "Gracefully shutting down container";
  // Use run_oci to perform graceful shutdown.
  std::vector<std::string> argv = {kRunOciPath, kRunOciLogging,
                                   kRunOciKillCommand, kContainerId};

  int exit_code = -1;
  if (!system_utils_->LaunchAndWait(argv, &exit_code)) {
    PLOG(ERROR) << "Failed to run run_oci";
    return false;
  } else if (exit_code) {
    LOG(ERROR) << "run_oci failed to gracefully shut down container \""
               << kContainerId << "\"";
    return false;
  }

  return true;
}

void AndroidOciWrapper::CleanUpContainer() {
  pid_t pid;
  if (!GetContainerPID(&pid))
    return;

  LOG(INFO) << "Cleaning up container " << pid;
  std::vector<std::string> argv = {kRunOciPath, kRunOciLogging,
                                   kRunOciConfigPath, kRunOciDestroyCommand,
                                   kContainerId};

  int exit_code = -1;
  if (!system_utils_->LaunchAndWait(argv, &exit_code)) {
    PLOG(ERROR) << "Failed to run run_oci";
  } else if (exit_code) {
    LOG(ERROR) << "run_oci failed to clean up resources for \"" << kContainerId
               << "\"";
  }

  // Save temporary values until everything is cleaned up.
  ExitCallback old_callback;
  std::swap(old_callback, exit_callback_);
  container_pid_ = 0;

  if (!old_callback.is_null())
    old_callback.Run(pid, exit_reason_);
}

bool AndroidOciWrapper::CloseOpenedFiles() {
  std::vector<base::FilePath> files;
  if (!system_utils_->EnumerateFiles(base::FilePath(kProcFdPath),
                                     base::FileEnumerator::FILES, &files)) {
    LOG(ERROR) << "Failed to enumerate files in " << kProcFdPath;
    return false;
  }

  for (const base::FilePath& file : files) {
    std::string name = file.BaseName().MaybeAsASCII();

    int fd;
    if (!base::StringToInt(name, &fd)) {
      LOG(WARNING) << "Skipped unparsable FD \"" << name << "\"";
      continue;
    }

    if (fd <= STDERR_FILENO)
      continue;

    if (system_utils_->close(fd)) {
      PLOG(ERROR) << "Failed to close FD " << fd;
      return false;
    }
  }

  return true;
}

void AndroidOciWrapper::KillProcessGroup(pid_t pgid) {
  CHECK_GT(pgid, 1);

  if (!system_utils_->ProcessGroupIsGone(pgid, base::TimeDelta()) &&
      system_utils_->kill(-pgid, -1, SIGKILL))
    PLOG(ERROR) << "Failed to kill run_oci pgroup";
}

}  // namespace login_manager
