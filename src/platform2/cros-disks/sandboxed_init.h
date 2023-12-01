// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_SANDBOXED_INIT_H_
#define CROS_DISKS_SANDBOXED_INIT_H_

#include <utility>

#include <sys/types.h>

#include <base/files/scoped_file.h>
#include <base/functional/callback.h>

namespace cros_disks {

// Anonymous pipe to establish communication between a parent process and a
// child process.
struct SubprocessPipe {
  base::ScopedFD child_fd, parent_fd;

  // Direction of communication.
  enum Direction { kChildToParent, kParentToChild };

  // Creates an open pipe. Sets FD_CLOEXEC on parent_fd. Dies in case of error.
  explicit SubprocessPipe(Direction direction);

  // Opens a pipe to communicate with a child process. Returns the end of the
  // pipe that is used by the child process. Stores the end of the pipe that is
  // kept by the parent process in *parent_fd and flags it with FD_CLOEXEC. Dies
  // in case of error.
  static base::ScopedFD Open(Direction direction, base::ScopedFD* parent_fd);
};

// To run daemons in a PID namespace under minijail we need to provide an 'init'
// process for the sandbox. As we rely on return code of the launcher of the
// daemonized process we must send it through a side channel back to the caller
// without waiting to the whole PID namespace to terminate.
class SandboxedInit {
 public:
  // Function to run in the 'launcher' process.
  using Launcher = base::OnceCallback<int()>;

  SandboxedInit(Launcher launcher,
                base::ScopedFD ctrl_fd,
                base::ScopedFD termination_fd = {})
      : launcher_(std::move(launcher)),
        ctrl_fd_(std::move(ctrl_fd)),
        termination_fd_(std::move(termination_fd)) {
    DCHECK(launcher_);
    DCHECK(ctrl_fd_.is_valid());
  }

  // This should be called in the 'init' process. Creates a child 'launcher'
  // process in which the |launcher| function is run. Monitors child processes
  // for termination. Terminates this 'init' process when there are no child
  // process anymore.
  [[noreturn]] void Run();

  // Reads and returns the exit code from |*ctrl_fd|. Returns -1 immediately if
  // no data is available yet. Closes |*ctrl_fd| once the exit code has been
  // read.
  //
  // Precondition: ctrl_fd != nullptr && ctrl_fd->is_valid()
  static int PollLauncher(base::ScopedFD* ctrl_fd);

  // Reads and returns the exit code from |*ctrl_fd|. Waits for data to be
  // available. Closes |*ctrl_fd| once the exit code has been read.
  //
  // Precondition: ctrl_fd != nullptr && ctrl_fd->is_valid()
  static int WaitForLauncher(base::ScopedFD* ctrl_fd);

  // Converts a process "wait status" (as returned by wait() and waitpid()) to
  // an exit code in the range 0 to 255. Returns -1 if the wait status |wstatus|
  // indicates that the process hasn't finished yet.
  static int WaitStatusToExitCode(int wstatus);

 private:
  // Creates a child 'launcher' process in which the launcher function is run.
  // Returns the PID of this 'launcher' process.
  pid_t StartLauncher();

  // Function to run in the 'launcher' process.
  Launcher launcher_;

  // Write end of the pipe into which the exit code of the launcher process is
  // written.
  base::ScopedFD ctrl_fd_;

  // Read end of termination pipe. SandboxInit configures this pipe so that it
  // terminates the init process when the write end is closed.
  base::ScopedFD termination_fd_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_SANDBOXED_INIT_H_
