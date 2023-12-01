// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/common/spawn_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <limits>
#include <memory>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace vm_tools {

namespace {

constexpr char kForkedProcessConsole[] = "/dev/null";
// Number of defined signals that the process could receive (not including
// real time signals).
constexpr int kNumSignals = 32;

// Resets all signal handlers to the default.  This is called in child processes
// immediately before exec-ing so that signals are not unexpectedly blocked.
// Returns 0 if all signal handlers were successfully set to their default
// dispositions.  Returns the signal number of the signal for which resetting
// the signal handler failed, if any.  Callers should inspect errno for the
// error.
int ResetSignalHandlers() {
  for (int signo = 1; signo < kNumSignals; ++signo) {
    if (signo == SIGKILL || signo == SIGSTOP) {
      // sigaction returns an error if we try to set the disposition of these
      // signals to SIG_DFL.
      continue;
    }
    struct sigaction act = {
        .sa_handler = SIG_DFL,
        .sa_flags = 0,
    };
    sigemptyset(&act.sa_mask);

    if (sigaction(signo, &act, nullptr) != 0) {
      return signo;
    }
  }

  return 0;
}

}  // namespace

bool Spawn(std::vector<std::string> argv,
           std::map<std::string, std::string> env,
           const std::string& working_dir,
           int stdio_fd[3],
           pid_t* spawned_pid) {
  CHECK(!argv.empty());

  // Build the argv.
  std::vector<const char*> argv_c(argv.size());
  std::transform(
      argv.begin(), argv.end(), argv_c.begin(),
      [](const std::string& arg) -> const char* { return arg.c_str(); });
  argv_c.emplace_back(nullptr);

  // Create a pair of sockets for communicating information about the child
  // process setup.  If there was an error in any of the steps performed before
  // running execvp, then the child process will send back a ChildErrorInfo
  // struct with the error details over the socket.  If the execvp runs
  // successful then the socket will automatically be closed (because of
  // the SOCK_CLOEXEC flag) and the parent will read 0 bytes from its end
  // of the socketpair.
  int info_fds[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, info_fds) != 0) {
    PLOG(ERROR) << "Failed to create socketpair for child process";
    return false;
  }

  // Block all signals before forking to prevent signals from arriving in the
  // child.
  sigset_t mask, omask;
  sigfillset(&mask);
  sigprocmask(SIG_BLOCK, &mask, &omask);

  pid_t pid = fork();
  if (pid < 0) {
    PLOG(ERROR) << "Failed to fork";
    return false;
  }

  if (pid == 0) {
    // Child process.
    close(info_fds[0]);

    DoChildSetup(env, working_dir, info_fds[1], stdio_fd);

    // Launch the process.
    execvp(argv_c[0], const_cast<char* const*>(argv_c.data()));

    // execvp never returns except in case of an error.
    struct ChildErrorInfo info = {
        .err = errno,
        .reason = ChildErrorInfo::Reason::EXEC,
    };

    send(info_fds[1], &info, sizeof(info), MSG_NOSIGNAL);
    _exit(errno);
  }

  // Parent process.
  close(info_fds[1]);
  struct ChildErrorInfo child_info = {};
  ssize_t ret = recv(info_fds[0], &child_info, sizeof(child_info), 0);

  bool retval = false;
  // There are 3 possibilities here:
  //   - The process setup completed successfully and the program was launched.
  //     In this case the socket fd in the child process will be closed on
  //     exec and ret will be 0.
  //   - An error occurred during setup.  ret will be sizeof(child_info).
  //   - An error occurred during the recv.  In this case we assume the child
  //     setup was successful.  If it wasn't, we'll find out about it through
  //     the normal child reaping mechanism.
  if (ret == sizeof(child_info)) {
    // Error occurred in the child.
    LOG(ERROR) << "Tried to spawn \"" << argv_c[0] << "\"";
    LogChildError(child_info, info_fds[0], working_dir);

    // Reap the child process here since we know it already failed.
    int status = 0;
    pid_t child = waitpid(pid, &status, 0);
    DCHECK_EQ(child, pid);
  } else if (ret < 0) {
    PLOG(ERROR) << "Failed to receive information about child process setup";
  } else {
    CHECK_EQ(ret, 0);
    retval = true;
    if (spawned_pid) {
      *spawned_pid = pid;
    }
  }
  close(info_fds[0]);
  // Restore the signal mask.
  sigprocmask(SIG_SETMASK, &omask, nullptr);
  return retval;
}

void DoChildSetup(const std::map<std::string, std::string>& env,
                  std::string working_dir,
                  int error_fd,
                  int stdio_fd[3]) {
  // Create a new session and process group.
  if (setsid() == -1) {
    struct ChildErrorInfo info = {
        .err = errno,
        .reason = ChildErrorInfo::Reason::SESSION_ID,
    };

    send(error_fd, &info, sizeof(info), MSG_NOSIGNAL);
    _exit(errno);
  }

  // File descriptor for the child's stdio in case it should be discarded.
  int null_fd = open(kForkedProcessConsole, O_RDWR | O_NOCTTY);
  if (null_fd < 0) {
    struct ChildErrorInfo info = {
        .err = errno,
        .reason = ChildErrorInfo::Reason::CONSOLE,
    };

    send(error_fd, &info, sizeof(info), MSG_NOSIGNAL);
    _exit(errno);
  }

  // Override the child's stdio fds with the fds specified in |stdio_fd|. If fd
  // specified in |stdio_fd| is -1 discards child's stdio by overriding it with
  // console fd.
  for (int newfd = 0; newfd < 3; ++newfd) {
    int fd = null_fd;
    if (stdio_fd[newfd] != -1) {
      fd = stdio_fd[newfd];
    }

    if (dup2(fd, newfd) < 0) {
      struct ChildErrorInfo info = {
          .details = {.fd = newfd},
          .err = errno,
          .reason = ChildErrorInfo::Reason::STDIO_FD,
      };

      send(error_fd, &info, sizeof(info), MSG_NOSIGNAL);
      _exit(errno);
    }
  }

  // Close the console fd, if necessary.
  if (null_fd >= 3) {
    close(null_fd);
  }

  // Set the umask back to a reasonable default.
  umask(0022);

  // Set the environment variables.
  for (const auto& pair : env) {
    if (setenv(pair.first.c_str(), pair.second.c_str(), 1) == 0) {
      continue;
    }

    // Failed to set an environment variable.  Send the error back to the
    // parent process.
    uint16_t env_length = 0;
    if (pair.first.size() + pair.second.size() + 2 <
        std::numeric_limits<uint16_t>::max()) {
      env_length =
          static_cast<uint16_t>(pair.first.size() + pair.second.size() + 2);
    }
    struct ChildErrorInfo info = {
        .details = {.env_length = env_length},
        .err = errno,
        .reason = ChildErrorInfo::Reason::SETENV,
    };
    send(error_fd, &info, sizeof(info), MSG_NOSIGNAL);

    // Also send back the offending (key, value) pair if it's not too long.
    // The pair is sent back in the format: <key>\0<value>\0.
    if (env_length != 0) {
      struct iovec iovs[] = {
          {
              .iov_base =
                  static_cast<void*>(const_cast<char*>(pair.first.data())),
              .iov_len = pair.first.size() + 1,
          },
          {
              .iov_base =
                  static_cast<void*>(const_cast<char*>(pair.second.data())),
              .iov_len = pair.second.size() + 1,
          },
      };
      struct msghdr hdr = {
          .msg_name = nullptr,
          .msg_namelen = 0,
          .msg_iov = iovs,
          .msg_iovlen = sizeof(iovs) / sizeof(iovs[0]),
          .msg_control = nullptr,
          .msg_controllen = 0,
          .msg_flags = 0,
      };
      sendmsg(error_fd, &hdr, MSG_NOSIGNAL);
    }
    _exit(errno);
  }

  // Set the working directory if requested.
  if (!working_dir.empty()) {
    if (chdir(working_dir.c_str())) {
      // If we failed, then send a failure message back to the parent process
      // and terminate the child process.
      struct ChildErrorInfo info = {
          .err = errno,
          .reason = ChildErrorInfo::Reason::WORKING_DIR,
      };
      send(error_fd, &info, sizeof(info), MSG_NOSIGNAL);
      _exit(errno);
    }
  }

  // Restore signal handlers and unblock all signals.
  int signo = ResetSignalHandlers();
  if (signo != 0) {
    struct ChildErrorInfo info = {
        .details = {.signo = signo},
        .err = errno,
        .reason = ChildErrorInfo::Reason::SIGNAL_RESET,
    };

    send(error_fd, &info, sizeof(info), MSG_NOSIGNAL);
    _exit(errno);
  }

  // Unblock all signals.
  sigset_t mask;
  sigfillset(&mask);
  sigprocmask(SIG_UNBLOCK, &mask, nullptr);
}

void LogChildError(const struct ChildErrorInfo& child_info,
                   int fd,
                   const std::string& working_dir) {
  const char* msg = nullptr;
  switch (child_info.reason) {
    case ChildErrorInfo::Reason::SESSION_ID:
      msg = "Failed to set session id in child process: ";
      break;
    case ChildErrorInfo::Reason::CONSOLE:
      msg = "Failed to open console in child process: ";
      break;
    case ChildErrorInfo::Reason::STDIO_FD:
      msg = "Failed to setup stdio file descriptors in child process: ";
      break;
    case ChildErrorInfo::Reason::SETENV:
      msg = "Failed to set environment variable in child process: ";
      break;
    case ChildErrorInfo::Reason::SIGNAL_RESET:
      msg = "Failed to reset signal handler disposition in child process: ";
      break;
    case ChildErrorInfo::Reason::EXEC:
      msg = "Failed to execute requested program in child process: ";
      break;
    case ChildErrorInfo::Reason::WORKING_DIR:
      msg = "Failed to set working directory in child process: ";
      break;
  }

  LOG(ERROR) << msg << strerror(child_info.err);

  if (child_info.reason == ChildErrorInfo::Reason::STDIO_FD) {
    LOG(ERROR) << "Unable to dup console fd to " << child_info.details.fd;
    return;
  }

  if (child_info.reason == ChildErrorInfo::Reason::SIGNAL_RESET) {
    LOG(ERROR) << "Unable to set signal disposition for signal "
               << child_info.details.signo << " to SIG_DFL";
    return;
  }

  if (child_info.reason == ChildErrorInfo::Reason::SETENV &&
      child_info.details.env_length > 0) {
    auto buf = std::make_unique<char[]>(child_info.details.env_length + 1);
    if (recv(fd, buf.get(), child_info.details.env_length, 0) !=
        child_info.details.env_length) {
      PLOG(ERROR) << "Unable to fetch error details from child process";
      return;
    }
    buf[child_info.details.env_length] = '\0';

    char* key = buf.get();
    char* value = strchr(buf.get(), '\0');
    if (value - key == child_info.details.env_length) {
      LOG(ERROR) << "Missing value in SETENV error details";
      return;
    }

    // Step over the nullptr at the end of |key|.
    ++value;

    LOG(ERROR) << "Unable to set " << key << " to " << value;
  }

  if (child_info.reason == ChildErrorInfo::Reason::WORKING_DIR) {
    LOG(ERROR) << "Unable to change to dir " << working_dir;
  }
}

}  // namespace vm_tools
