// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/sandboxed_init.h"

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/file_descriptor_posix.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/scoped_clear_last_error.h>
#include <brillo/syslog_logging.h>
#include <chromeos/libminijail.h>

#include "cros-disks/process.h"

namespace cros_disks {
namespace {

[[noreturn]] void TerminateNow() {
  RAW_LOG(INFO, "The 'init' process is terminating now");
  _exit(128 + SIGKILL);
}

// SIGALRM handler.
void SigAlarm(const int sig) {
  const base::ScopedClearLastError guard;

  if (sig != SIGALRM) {
    RAW_LOG(ERROR, "SIGALRM handler called with sig != SIGALRM");
    return;
  }

  RAW_LOG(INFO, "The 'init' process's grace period expired");
  TerminateNow();
}

void ScheduleTermination() {
  if (getpid() != 1)
    TerminateNow();

  // This is running as the 'init' process of a PID namespace.
  if (signal(SIGTERM, SIG_IGN) == SIG_ERR)
    RAW_LOG(ERROR, "Cannot reset SIGTERM handler");

  // Send SIGTERM to all the processes in the PID namespace.
  RAW_LOG(INFO, "The 'init' process is broadcasting SIGTERM...");
  if (kill(-1, SIGTERM) < 0)
    RAW_LOG(ERROR, "The 'init' process cannot broadcast SIGTERM");

  // Set an alarm to terminate in a couple of seconds.
  RAW_LOG(INFO, "The 'init' process is entering a grace period of 2 seconds");

  if (signal(SIGALRM, &SigAlarm) == SIG_ERR)
    RAW_LOG(ERROR, "Cannot set SIGALRM handler");

  if (alarm(2) != 0)
    RAW_LOG(ERROR, "A previous alarm was already set");
}

// File descriptor of the termination pipe.
// Static and volatile since it is accessed from signal handlers.
static volatile int termination_fd = base::kInvalidFd;

// SIGTERM handler.
void SigTerm(const int sig) {
  const base::ScopedClearLastError guard;

  if (sig != SIGTERM) {
    RAW_LOG(ERROR, "SIGTERM handler called with sig != SIGTERM");
    return;
  }

  RAW_LOG(INFO, "The 'init' process received SIGTERM");

  // If no termination fd is set, then we shouldn't forcefully terminate.
  if (termination_fd == base::kInvalidFd) {
    RAW_LOG(WARNING, "The 'init' process ignored a SIGTERM");
    return;
  }

  ScheduleTermination();
}

// Check if the termination pipe has some data or if its write end has been
// closed.
bool ShouldTerminate() {
  if (termination_fd == base::kInvalidFd)
    return false;

  if (char buffer; read(termination_fd, &buffer, sizeof(buffer)) < 0) {
    if (errno != EAGAIN)
      RAW_LOG(ERROR, "Reading from termination fd returned error != EAGAIN");
    return false;
  }

  return true;
}

// SIGIO handler.
void SigIo(const int sig) {
  const base::ScopedClearLastError guard;

  if (sig != SIGIO) {
    RAW_LOG(ERROR, "SIGIO handler called with sig != SIGIO");
    return;
  }

  RAW_LOG(INFO, "The 'init' process received SIGIO");
  if (ShouldTerminate())
    ScheduleTermination();
}

}  // namespace

SubprocessPipe::SubprocessPipe(const Direction direction) {
  int fds[2];
  PCHECK(pipe(fds) >= 0);
  child_fd.reset(fds[1 - direction]);
  parent_fd.reset(fds[direction]);
  PCHECK(base::SetCloseOnExec(parent_fd.get()));
}

base::ScopedFD SubprocessPipe::Open(const Direction direction,
                                    base::ScopedFD* const parent_fd) {
  DCHECK(parent_fd);

  SubprocessPipe p(direction);
  *parent_fd = std::move(p.parent_fd);
  return std::move(p.child_fd);
}

[[noreturn]] void SandboxedInit::Run() {
  // To run our custom init that handles daemonized processes inside the
  // sandbox we have to set up fork/exec ourselves. We do error-handling
  // the "minijail-style" - abort if something not right.

  // This performs as the init process in the jail PID namespace (PID 1).
  // Redirect in/out so logging can communicate assertions and children
  // to inherit right FDs.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  // Set an identifiable process name.
  PCHECK(prctl(PR_SET_NAME, "cros-disks-init") >= 0);

  // Set up the SIGTERM signal handler.
  PCHECK(signal(SIGTERM, SigTerm) != SIG_ERR);

  // Set up the SIGPIPE signal handler. Since we write to the control pipe, we
  // don't want this 'init' process to be killed by a SIGPIPE.
  PCHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);

  if (termination_fd_.is_valid()) {
    // Save termination_fd to global variable to it's accessible from the signal
    // handler.
    termination_fd = termination_fd_.get();

    // Set up the SIGIO signal handler to monitor termination_fd.
    PCHECK(signal(SIGIO, SigIo) != SIG_ERR);
    PCHECK(fcntl(termination_fd, F_SETOWN, getpid()) >= 0);
    PCHECK(fcntl(termination_fd, F_SETFL, O_ASYNC | O_NONBLOCK) >= 0);
    if (ShouldTerminate())
      TerminateNow();
  }

  // PID of the launcher process inside the jail PID namespace (e.g. PID 2).
  const pid_t launcher_pid = StartLauncher();

  DCHECK(ctrl_fd_.is_valid());
  PCHECK(base::SetNonBlocking(ctrl_fd_.get()));

  // Close stdin and stdout. Keep stderr open, so that error messages can still
  // be logged.
  IGNORE_EINTR(close(STDIN_FILENO));
  IGNORE_EINTR(close(STDOUT_FILENO));

  // This loop will only end when either there are no processes left inside
  // our PID namespace or we get a signal.
  Process::ExitCode last_failure_code = Process::ExitCode::kSuccess;

  while (true) {
    // Wait for any child process to terminate.
    int wstatus;
    const pid_t pid = HANDLE_EINTR(wait(&wstatus));

    if (pid < 0) {
      PCHECK(errno == ECHILD);

      // No more child. By then, we should have closed the control pipe.
      DCHECK(!ctrl_fd_.is_valid());
      VLOG(2) << "The 'init' process is finishing with " << last_failure_code;
      _exit(static_cast<int>(last_failure_code));
    }

    // A child process finished.
    // Convert wait status to exit code.
    const Process::ExitCode exit_code =
        static_cast<Process::ExitCode>(WaitStatusToExitCode(wstatus));
    DCHECK_GE(static_cast<int>(exit_code), 0);
    VLOG(2) << "Child process " << pid
            << " of the 'init' process finished with " << exit_code;

    if (exit_code != Process::ExitCode::kSuccess)
      last_failure_code = exit_code;

    // Was it the 'launcher' process?
    if (pid != launcher_pid)
      continue;

    // Write the 'launcher' process's exit code to the control pipe.
    DCHECK(ctrl_fd_.is_valid());
    const ssize_t written =
        HANDLE_EINTR(write(ctrl_fd_.get(), &exit_code, sizeof(exit_code)));
    PLOG_IF(ERROR,
            written != sizeof(exit_code) && (LOG_IS_ON(INFO) || errno != EPIPE))
        << "Cannot write " << exit_code
        << " returned by the 'launcher' process " << launcher_pid << " to pipe "
        << ctrl_fd_.get();

    // Close the control pipe.
    ctrl_fd_.reset();
  }

  NOTREACHED();
}

pid_t SandboxedInit::StartLauncher() {
  const pid_t launcher_pid = fork();
  PCHECK(launcher_pid >= 0);

  if (launcher_pid > 0) {
    // In parent (ie 'init') process.
    return launcher_pid;
  }

  // In 'launcher' process.
  // Avoid leaking file descriptor into launcher process.
  DCHECK(ctrl_fd_.is_valid());
  ctrl_fd_.reset();

  // Run the launcher function.
  _exit(std::move(launcher_).Run());
  NOTREACHED();
}

int SandboxedInit::PollLauncher(base::ScopedFD* const ctrl_fd) {
  DCHECK(ctrl_fd);
  DCHECK(ctrl_fd->is_valid());

  const int fd = ctrl_fd->get();
  int exit_code;
  const ssize_t read_bytes =
      HANDLE_EINTR(read(fd, &exit_code, sizeof(exit_code)));

  // If an error occurs while reading from the pipe, consider that the init
  // process was killed before it could even write to the pipe.
  const int error_code = MINIJAIL_ERR_SIG_BASE + SIGKILL;

  if (read_bytes < 0) {
    // Cannot read data from pipe.
    if (errno == EAGAIN) {
      VLOG(2) << "Nothing to read from control pipe " << fd;
      return -1;
    }

    PLOG(ERROR) << "Cannot read from control pipe " << fd;
    exit_code = error_code;
  } else if (read_bytes < sizeof(exit_code)) {
    // Cannot read enough data from pipe.
    DCHECK_GE(read_bytes, 0);
    LOG(ERROR) << "Short read of " << read_bytes << " bytes from control pipe "
               << fd;
    exit_code = error_code;
  } else {
    DCHECK_EQ(read_bytes, sizeof(exit_code));
    VLOG(2) << "Received exit code " << exit_code << " from control pipe "
            << fd;
    DCHECK_GE(exit_code, 0);
    DCHECK_LE(exit_code, 255);
  }

  ctrl_fd->reset();
  return exit_code;
}

int SandboxedInit::WaitForLauncher(base::ScopedFD* const ctrl_fd) {
  while (true) {
    DCHECK(ctrl_fd);
    DCHECK(ctrl_fd->is_valid());

    struct pollfd pfd = {.fd = ctrl_fd->get(), .events = POLLIN};
    const int n = HANDLE_EINTR(poll(&pfd, 1, /* timeout = */ -1));
    PLOG_IF(ERROR, n < 0) << "Cannot poll control pipe " << pfd.fd;

    if (const int exit_code = PollLauncher(ctrl_fd); exit_code >= 0)
      return exit_code;
  }
}

int SandboxedInit::WaitStatusToExitCode(int wstatus) {
  if (WIFEXITED(wstatus)) {
    return WEXITSTATUS(wstatus);
  }

  if (WIFSIGNALED(wstatus)) {
    // Mirrors behavior of minijail_wait().
    const int signum = WTERMSIG(wstatus);
    return signum == SIGSYS ? MINIJAIL_ERR_JAIL
                            : MINIJAIL_ERR_SIG_BASE + signum;
  }

  return -1;
}

}  // namespace cros_disks
