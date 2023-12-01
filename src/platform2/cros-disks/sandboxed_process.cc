// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/sandboxed_process.h"

#include <iostream>
#include <utility>

#include <stdlib.h>

#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/safe_strerror.h>
#include <chromeos/libminijail.h>

#include "cros-disks/quote.h"

namespace cros_disks {
namespace {

void SimulateProgressForTesting() {
  PCHECK(signal(SIGTERM, SIG_IGN) != SIG_ERR);
  for (int i = 0; i < 100; ++i) {
    std::cerr << "Simulating progress " << i << "%" << std::endl;
    usleep(100'000);
  }
  PCHECK(signal(SIGTERM, SIG_DFL) != SIG_ERR);
}

int Exec(char* const args[],
         char* const env[],
         const bool simulate_progress_for_testing) {
  if (simulate_progress_for_testing)
    SimulateProgressForTesting();

  const char* const path = args[0];
  execve(path, args, env);
  const int ret =
      (errno == ENOENT ? MINIJAIL_ERR_NO_COMMAND : MINIJAIL_ERR_NO_ACCESS);
  PLOG(ERROR) << "Cannot exec " << quote(path);
  return ret;
}

}  // namespace

SandboxedProcess::SandboxedProcess() : jail_(minijail_new()) {
  CHECK(jail_) << "Failed to create a process jail";
}

SandboxedProcess::~SandboxedProcess() {
  minijail_destroy(jail_);
}

void SandboxedProcess::LoadSeccompFilterPolicy(const std::string& policy_file) {
  minijail_parse_seccomp_filters(jail_, policy_file.c_str());
  minijail_use_seccomp_filter(jail_);
}

void SandboxedProcess::NewCgroupNamespace() {
  minijail_namespace_cgroups(jail_);
}

void SandboxedProcess::NewIpcNamespace() {
  minijail_namespace_ipc(jail_);
}

void SandboxedProcess::NewMountNamespace() {
  minijail_namespace_vfs(jail_);
}

void SandboxedProcess::EnterExistingMountNamespace(const std::string& ns_path) {
  minijail_namespace_enter_vfs(jail_, ns_path.c_str());
}

void SandboxedProcess::NewPidNamespace() {
  minijail_namespace_pids(jail_);
  minijail_run_as_init(jail_);
  minijail_reset_signal_mask(jail_);
  minijail_reset_signal_handlers(jail_);
  minijail_skip_remount_private(jail_);  // crbug.com/1008262
  use_pid_namespace_ = true;
}

bool SandboxedProcess::SetUpMinimalMounts() {
  if (minijail_bind(jail_, "/", "/", 0))
    return false;
  if (minijail_bind(jail_, "/proc", "/proc", 0))
    return false;
  minijail_remount_proc_readonly(jail_);
  minijail_mount_tmp_size(jail_, 128 * 1024 * 1024);

  // Create a minimal /dev with a very restricted set of device nodes.
  minijail_mount_dev(jail_);
  if (minijail_bind(jail_, "/dev/log", "/dev/log", 0))
    return false;
  return true;
}

bool SandboxedProcess::BindMount(const std::string& from,
                                 const std::string& to,
                                 bool writeable,
                                 bool recursive) {
  int flags = MS_BIND;
  if (!writeable) {
    flags |= MS_RDONLY;
  }
  if (recursive) {
    flags |= MS_REC;
  }
  return minijail_mount(jail_, from.c_str(), to.c_str(), "", flags) == 0;
}

bool SandboxedProcess::Mount(const std::string& src,
                             const std::string& to,
                             const std::string& type,
                             const char* data) {
  return minijail_mount_with_data(jail_, src.c_str(), to.c_str(), type.c_str(),
                                  0, data) == 0;
}

bool SandboxedProcess::EnterPivotRoot() {
  return minijail_enter_pivot_root(jail_, "/mnt/empty") == 0;
}

void SandboxedProcess::NewNetworkNamespace() {
  // As of 2021-08-04, this can log a warning to /var/log/messages:
  // "ioctl(SIOCSIFFLAGS) failed: Operation not permitted"
  //
  // This libminijail message is harmless: https://crbug.com/1226229
  minijail_namespace_net(jail_);
}

void SandboxedProcess::SetNoNewPrivileges() {
  minijail_no_new_privs(jail_);
}

void SandboxedProcess::SetCapabilities(uint64_t capabilities) {
  minijail_use_caps(jail_, capabilities);
}

void SandboxedProcess::SetGroupId(gid_t group_id) {
  minijail_change_gid(jail_, group_id);
}

void SandboxedProcess::SetUserId(uid_t user_id) {
  minijail_change_uid(jail_, user_id);
}

void SandboxedProcess::SetSupplementaryGroupIds(base::span<const gid_t> gids) {
  minijail_set_supplementary_gids(jail_, gids.size(), gids.data());
}

bool SandboxedProcess::AddToCgroup(const std::string& cgroup) {
  return minijail_add_to_cgroup(jail_, cgroup.c_str()) == 0;
}

void SandboxedProcess::PreserveFile(int fd) {
  if (const int ret = minijail_preserve_fd(jail_, fd, fd)) {
    LOG(FATAL) << "Cannot preserve file descriptor " << fd << ": "
               << base::safe_strerror(-ret);
  }
}

pid_t SandboxedProcess::StartImpl(base::ScopedFD in_fd, base::ScopedFD out_fd) {
  char* const* const args = GetArguments();
  DCHECK(args && args[0]);
  char* const* const env = GetEnvironment();
  DCHECK(env);

  pid_t child_pid = kInvalidProcessId;

  minijail_close_open_fds(jail_);

  // Set up stdin, stdout and stderr to be connected to the matching pipes in
  // the jailed process.
  CHECK_EQ(minijail_preserve_fd(jail_, in_fd.get(), STDIN_FILENO), 0);
  CHECK_EQ(minijail_preserve_fd(jail_, out_fd.get(), STDOUT_FILENO), 0);
  CHECK_EQ(minijail_preserve_fd(jail_, out_fd.get(), STDERR_FILENO), 0);

  if (!use_pid_namespace_) {
    if (const int ret = minijail_run_env_pid_pipes(
            jail_, args[0], args, env, &child_pid, nullptr, nullptr, nullptr);
        ret < 0) {
      errno = -ret;
      PLOG(ERROR) << "Cannot start minijail process";
      return kInvalidProcessId;
    }
  } else {
    // The sandboxed process will run in a PID namespace.
    PreserveFile(launcher_pipe_.child_fd.get());

    SubprocessPipe termination_pipe(SubprocessPipe::kParentToChild);
    PreserveFile(termination_pipe.child_fd.get());

    // Create child 'init' process in the PID namespace.
    child_pid = minijail_fork(jail_);
    if (child_pid < 0) {
      errno = -child_pid;
      PLOG(ERROR) << "Cannot run minijail_fork";
      return kInvalidProcessId;
    }

    if (child_pid == 0) {
      // In child 'init' process.
      SandboxedInit(
          base::BindOnce(Exec, args, env, simulate_progress_for_testing_),
          std::move(launcher_pipe_.child_fd),
          kill_pid_namespace_ ? std::move(termination_pipe.child_fd)
                              : base::ScopedFD())
          .Run();
      NOTREACHED();
    } else {
      // In parent process.
      PCHECK(base::SetNonBlocking(launcher_pipe_.parent_fd.get()));
      launcher_pipe_.child_fd.reset();

      DCHECK(!termination_fd_.is_valid());
      termination_fd_ = std::move(termination_pipe.parent_fd);
      DCHECK(termination_fd_.is_valid());
    }
  }

  return child_pid;
}

int SandboxedProcess::WaitImpl() {
  if (use_pid_namespace_) {
    launcher_watch_.reset();
    return SandboxedInit::WaitForLauncher(&launcher_pipe_.parent_fd);
  }

  while (true) {
    const int status = minijail_wait(jail_);
    if (status >= 0)
      return status;

    if (const int err = -status; err != EINTR) {
      LOG(ERROR) << "Cannot wait for process " << pid() << ": "
                 << base::safe_strerror(err);
      return MINIJAIL_ERR_INIT;
    }
  }
}

int SandboxedProcess::WaitNonBlockingImpl() {
  if (use_pid_namespace_) {
    const int exit_code =
        SandboxedInit::PollLauncher(&launcher_pipe_.parent_fd);
    if (exit_code >= 0)
      launcher_watch_.reset();
    return exit_code;
  }

  // TODO(chromium:971667) Use Minijail's non-blocking wait once it exists.
  int wstatus;
  const pid_t child_pid = pid();
  const int ret = waitpid(child_pid, &wstatus, WNOHANG);
  if (ret < 0) {
    PLOG(ERROR) << "Cannot wait for process " << child_pid;
    return MINIJAIL_ERR_INIT;
  }

  if (ret == 0) {
    // Process is still running.
    return -1;
  }

  return SandboxedInit::WaitStatusToExitCode(wstatus);
}

bool SandboxedProcess::KillPidNamespace() {
  if (!termination_fd_.is_valid())
    return false;

  DCHECK(kill_pid_namespace_);

  // Closing termination_fd_ will eventually cause the termination of the 'init'
  // process of the PID namespace.
  termination_fd_.reset();
  LOG(INFO) << "Requested termination of " << quote(GetProgramName());
  return true;
}

int FakeSandboxedProcess::OnProcessLaunch(
    const std::vector<std::string>& argv) {
  return 0;
}

pid_t FakeSandboxedProcess::StartImpl(base::ScopedFD, base::ScopedFD) {
  DCHECK(!ret_code_);
  ret_code_ = OnProcessLaunch(arguments());
  return 42;
}

int FakeSandboxedProcess::WaitImpl() {
  DCHECK(ret_code_);
  return ret_code_.value();
}

int FakeSandboxedProcess::WaitNonBlockingImpl() {
  if (ret_code_)
    return ret_code_.value();
  return -1;
}

}  // namespace cros_disks
