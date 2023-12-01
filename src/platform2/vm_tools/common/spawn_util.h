// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_COMMON_SPAWN_UTIL_H_
#define VM_TOOLS_COMMON_SPAWN_UTIL_H_

#include <map>
#include <string>
#include <vector>

namespace vm_tools {

// Information about any errors that happen in the child process before the exec
// call.  This is sent back to the parent process via a socket.
struct __attribute__((packed)) ChildErrorInfo {
  enum class Reason : uint8_t {
    // Failed to set session id.
    SESSION_ID = 0,
    // Unable to open console.
    CONSOLE = 1,
    // Unable to set stdio fds.
    STDIO_FD = 2,
    // Unable to set environment variable.
    SETENV = 3,
    // Unable to reset signal handlers.
    SIGNAL_RESET = 4,
    // Failed to exec the requested program.
    EXEC = 5,
    // Failed to set the working directory.
    WORKING_DIR = 6,
  };

  union {
    // If |reason| is STDIO_FD, the fd that we failed to dup.
    int32_t fd;

    // If |reason| is SETENV, then the child process will append the key and
    // value of the environment variable pair that failed to this struct.  This
    // value tells the parent process the length of the 2 strings, including the
    // '\0' byte for each string.
    uint16_t env_length;

    // If |reason| is SIGNAL_RESET, the signal number for which we failed to set
    // the default disposition.
    int32_t signo;
  } details;

  // The errno value after the failed action.
  int32_t err;

  // Error reason.
  Reason reason;
};

// Executed a process with the specified |argv| arguments using the |env|
// environment. If |working_dir| is not empty, it is executed inside of that
// working directory. Redirects child's stdio to |stdio_fd|, discards io for
// fds specified as -1.
// Returns true on successful execution, false otherwise.
// On success, the forked process's process ID is stored in |spawned_pid| if
// it is non-null.
bool Spawn(std::vector<std::string> argv,
           std::map<std::string, std::string> env,
           const std::string& working_dir,
           int stdio_fd[3],
           pid_t* spawned_pid = nullptr);

// Performs various setup steps in the child process after calling fork() but
// before calling exec(). |error_fd| should be a valid file descriptor for a
// socket and will be used to send error information back to the parent process
// if any of the setup steps fail. |stdio_fd| should contain valid fds or -1,
// child's stdio would be redirected to the specified fds or discarded in case
// -1 is specified.
void DoChildSetup(const std::map<std::string, std::string>& env,
                  std::string working_dir,
                  int error_fd,
                  int stdio_fd[3]);

// Logs information about the error that occurred in the child process.
void LogChildError(const struct ChildErrorInfo& child_info,
                   int fd,
                   const std::string& working_dir);

}  // namespace vm_tools

#endif  // VM_TOOLS_COMMON_SPAWN_UTIL_H_
