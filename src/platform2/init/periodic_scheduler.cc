// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/periodic_scheduler.h"

#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/threading/platform_thread.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>

namespace {
constexpr base::TimeDelta kCheckDelay = base::Minutes(5);
constexpr base::TimeDelta kKillDelay = base::Seconds(10);
constexpr char kSpoolDir[] = "/var/spool";
constexpr char kSpoolCronLiteDir[] = "cron-lite";

// Make sure that the path is a directory.
bool SanitizePath(const base::FilePath& path) {
  struct stat path_stat;
  // Avoid weird spool paths if possible.
  if (lstat(path.value().c_str(), &path_stat) != 0 ||
      !S_ISDIR(path_stat.st_mode)) {
    // Don't recursively delete the directory if we can't stat it.
    brillo::DeleteFile(path);
    if (!base::CreateDirectory(path)) {
      PLOG(ERROR) << "Failed to create new directory " << path.value();
      return false;
    }
  }

  return true;
}

bool CheckAndFixSpoolPaths(const base::FilePath& spool_dir) {
  return SanitizePath(spool_dir) &&
         SanitizePath(spool_dir.Append(kSpoolCronLiteDir));
}

base::Time GetPathMtime(const base::FilePath& path) {
  struct stat path_stat;
  if (stat(path.value().c_str(), &path_stat)) {
    PLOG(WARNING) << "Failed to get mtime for file " << path.value();
    return base::Time::FromTimeT(0);
  }

  return base::Time::FromTimeT(path_stat.st_mtime);
}

// Sets up PR_SET_PDEATHSIG to send SIGKILLs to the running subprocesses in case
// the scheduler process crashes/exits.
class TerminateWithParentDelegate
    : public base::LaunchOptions::PreExecDelegate {
 public:
  TerminateWithParentDelegate() = default;
  ~TerminateWithParentDelegate() = default;

  void RunAsyncSafe() override { prctl(PR_SET_PDEATHSIG, SIGKILL); }
};

// Atomic variable for holding the child pid.
static std::atomic<base::ProcessId> child_pid(-1);

// Handle SIGTERM by sending the signal to current active child process, wait
// for the child process to complete and exit. This allows the periodic
// scheduler (and its subprocesses) to exit gracefully when the init process
// (Upstart) sends it a SIGTERM.
//
// If the child process does not exit on SIGTERM, subsequently the periodic
// scheduler process will exit/be killed and the configured PDEATHSIG (SIGKILL)
// is sent to the child processes.
static void SigtermHandler(int signal) {
  if (child_pid > 0) {
    // Attempt to send SIGTERM to the child process and wait for the child
    // process to exit.
    base::Process p(child_pid);
    p.Terminate(-1, false /* wait */);
    p.WaitForExitWithTimeout(kKillDelay, nullptr);
  }
  exit(0);
}

// Register signal handler for handling SIGTERM and stopping the process.
void RegisterSigtermHandler() {
  struct sigaction sigterm_action = {};
  sigemptyset(&sigterm_action.sa_mask);
  sigterm_action.sa_flags = SA_RESTART;
  sigaddset(&sigterm_action.sa_mask, SIGTERM);
  sigterm_action.sa_handler = SigtermHandler;
  CHECK_EQ(sigaction(SIGTERM, &sigterm_action, nullptr), 0);
}

}  // namespace

PeriodicScheduler::PeriodicScheduler(
    const base::TimeDelta& period,
    const base::TimeDelta& timeout,
    const std::string& task_name,
    const std::vector<std::string>& task_command)
    : period_seconds_(period),
      timeout_seconds_(timeout),
      check_frequency_(kCheckDelay + kKillDelay),
      task_name_(task_name),
      spool_dir_(base::FilePath(kSpoolDir)),
      process_args_(task_command) {}

bool PeriodicScheduler::Run(bool start_immediately) {
  RegisterSigtermHandler();

  if (!CheckAndFixSpoolPaths(spool_dir_)) {
    LOG(ERROR) << "Spool directory is damaged. Aborting!";
    return false;
  }

  const base::FilePath spool_file =
      spool_dir_.Append(kSpoolCronLiteDir).Append(task_name_);

  while (true) {
    if (!start_immediately) {
      if (!base::PathExists(spool_file)) {
        base::WriteFile(spool_file, nullptr, 0);
        auto now = base::Time::Now();
        base::TouchFile(spool_file, now, now);
      }
      base::PlatformThread::Sleep(check_frequency_);
    }

    auto file_last_mtime = GetPathMtime(spool_file);
    auto current_time = base::Time::Now();

    if (start_immediately || current_time - file_last_mtime > period_seconds_) {
      brillo::DeleteFile(spool_file);
      base::WriteFile(spool_file, nullptr, 0);
      auto now = base::Time::Now();
      base::TouchFile(spool_file, now, now);

      int exit_code;
      base::LaunchOptions opts;
      TerminateWithParentDelegate terminate_with_parent_delegate;
      opts.pre_exec_delegate = &terminate_with_parent_delegate;
      auto p = base::LaunchProcess(process_args_, opts);
      child_pid = p.Pid();
      LOG(INFO) << task_name_ << ": running "
                << base::JoinString(process_args_, " ");

      if (!p.IsValid()) {
        PLOG(ERROR) << "Failed to launch process";
        return false;
      }

      if (!p.WaitForExitWithTimeout(timeout_seconds_, &exit_code)) {
        LOG(ERROR) << task_name_ << ": timed out";
        p.Terminate(-1, true /* wait */);
        child_pid = -1;
      }

      if (exit_code != EXIT_SUCCESS) {
        LOG(ERROR) << task_name_ << ": process exited " << exit_code;
      }

      LOG(INFO) << task_name_ << ": job completed";
    }

    start_immediately = false;
  }
}
