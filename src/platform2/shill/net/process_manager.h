// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_PROCESS_MANAGER_H_
#define SHILL_NET_PROCESS_MANAGER_H_

#include <sys/types.h>  // for rlim_t

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/containers/flat_set.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/lazy_instance.h>
#include <base/location.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>

#include <brillo/minijail/minijail.h>
#include <brillo/process/process.h>
#include <brillo/process/process_reaper.h>
#include <libminijail.h>

#include "shill/net/shill_export.h"

namespace shill {

struct SHILL_EXPORT std_file_descriptors {
  int* stdin_fd;
  int* stdout_fd;
  int* stderr_fd;
};

// The ProcessManager is a singleton providing process creation and
// asynchronous process termination. Need to initialize it once with
// Init method call.
class SHILL_EXPORT ProcessManager {
 public:
  using ExitCallback = base::OnceCallback<void(int exit_status)>;
  using ExitWithStdoutCallback =
      base::OnceCallback<void(int exit_status, const std::string& stdout_str)>;

  struct SHILL_EXPORT MinijailOptions {
    // Program will run as |user| and |group|.
    std::string user;
    std::string group;
    // Provides the child process with capabilities, which |user| might not have
    // on its own.
    uint64_t capmask = 0;
    // Allows child process to inherit supplementary groups from uid, equivalent
    // to using '-G' on the minijail command line.
    bool inherit_supplementary_groups = false;
    // Set of non-standard file descriptors to be inherited by the child
    // process.
    base::flat_set<int> preserved_nonstd_fds;
    // If set, the soft limit of the maximum size of the process's virtual
    // memory (RLIMIT_AS) will be set to this value. See getrlimit(2).
    std::optional<rlim_t> rlimit_as_soft;
  };

  static constexpr base::TimeDelta kTerminationTimeout = base::Seconds(2);
  static constexpr pid_t kInvalidPID = -1;

  virtual ~ProcessManager();

  // This is a singleton -- use ProcessManager::GetInstance()->Foo().
  static ProcessManager* GetInstance();

  // Register async signal handler and setup process reaper.
  virtual void Init();

  // Call on shutdown to release async_signal_handler_.
  virtual void Stop();

  // Create and start a process for |program| with |arguments|.
  // |environment| variables will be setup in the child process before executing
  // the |program|.
  // |fds_to_bind| is used to bind the file descriptors between the parent
  // process and child process. The pair of int is the file descriptors at the
  // parent process and child process.
  // |terminate_with_parent| is used to indicate if child process should self
  // terminate if the parent process exits.
  // |exit_callback| will be invoked when child process exits (not terminated by
  // us).
  // Return kInvalidPID if failed to start the process, otherwise, return the
  // pid of the child process.
  virtual pid_t StartProcess(
      const base::Location& spawn_source,
      const base::FilePath& program,
      const std::vector<std::string>& arguments,
      const std::map<std::string, std::string>& environment,
      const std::vector<std::pair<int, int>>& fds_to_bind,
      bool terminate_with_parent,
      ExitCallback exit_callback);

  // Similar to StartProcess(), with the following differences:
  // - terminate_with_parent is not supported (may be non-trivial).
  // - |minijail_options| will be applied when starting the process in minijail.
  //   See the comments for MinijailOptions above for the available options.
  virtual pid_t StartProcessInMinijail(
      const base::Location& spawn_source,
      const base::FilePath& program,
      const std::vector<std::string>& arguments,
      const std::map<std::string, std::string>& environment,
      const MinijailOptions& minijail_options,
      ExitCallback exit_callback) {
    return StartProcessInMinijailWithPipes(
        spawn_source, program, arguments, environment, minijail_options,
        std::move(exit_callback),
        (struct std_file_descriptors){nullptr, nullptr, nullptr});
  }

  // Similar to StartProcessInMinijail(), with the additional ability to
  // pipe the child's stdin/stdout/stderr back to us. If any of those
  // streams is not needed, simply pass nullptr for the corresponding
  // member in std file descriptor struct. If no pipes are needed, use
  // StartProcessInMinijail().
  virtual pid_t StartProcessInMinijailWithPipes(
      const base::Location& spawn_source,
      const base::FilePath& program,
      const std::vector<std::string>& arguments,
      const std::map<std::string, std::string>& environment,
      const MinijailOptions& minijail_options,
      ExitCallback exit_callback,
      struct std_file_descriptors std_fds);

  // Similar to StartProcessInMinijail, with the additional ability to return
  // the output of stdout with the exit status together when the program exits.
  // Note that the output of stdout will be cached inside this object during the
  // lifetime of the process, so this function may not be suitable for the
  // processes which will run for a long time and output a lot in stdout.
  // Currently, this class will only keep 32KB at maximum for the stdout of a
  // process. Any string beyond that length will be truncated.
  virtual pid_t StartProcessInMinijailWithStdout(
      const base::Location& spawn_source,
      const base::FilePath& program,
      const std::vector<std::string>& arguments,
      const std::map<std::string, std::string>& environment,
      const MinijailOptions& minijail_options,
      ExitWithStdoutCallback exit_callback);

  // Stop the given |pid|.  Previously registered |exit_callback| will be
  // unregistered, since the caller is not interested in this process anymore
  // and that callback might not be valid by the time this process terminates.
  // This will attempt to terminate the child process by sending a SIGTERM
  // signal first.  If the process doesn't terminate within a certain time,
  // ProcessManager will attempt to send a SIGKILL signal.  It will give up
  // with an error log If the process still doesn't terminate within a certain
  // time.
  virtual bool StopProcess(pid_t pid);

  // Stop the given |pid| in a synchronous manner.
  virtual bool StopProcessAndBlock(pid_t pid);

  // Replace the current exit callback for |pid| with |new_callback|.
  virtual bool UpdateExitCallback(pid_t pid, ExitCallback new_callback);

  // Checks whether the old charon process is alive still alive after sending a
  // SIGTERM to it or not. Returns std::nullopt on error.
  virtual std::optional<bool> IsTerminating(const base::FilePath& pid_path);

 protected:
  ProcessManager();
  ProcessManager(const ProcessManager&) = delete;
  ProcessManager& operator=(const ProcessManager&) = delete;

 private:
  friend class ProcessManagerTest;
  friend base::LazyInstanceTraitsBase<ProcessManager>;

  using TerminationTimeoutCallback = base::CancelableOnceClosure;

  struct WatchedProcess {
    // |exit_callback| is valid when the caller only expects the exit status.
    // |exit_with_stdout_callback| is valid when the caller also expects the
    // output of stdout. One and only one of these two callbacks can be valid at
    // the same time.
    ExitCallback exit_callback;
    ExitWithStdoutCallback exit_with_stdout_callback;

    // The exit status if the process has already exited.
    std::optional<int> exit_status;

    // Fields related to stdout of this watched process. They are meaningful
    // only when |exit_with_stdout_callback| is set. |stdout_fd| and
    // |stdout_watcher| will be set once the process is started, and be reset
    // once the stdout pipe is closed.
    base::ScopedFD stdout_fd;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> stdout_watcher;
    std::string stdout_str;
  };

  // See the above comment for StartProcessInMinijailWithPipes().
  pid_t StartProcessInMinijailWithPipesInternal(
      const base::Location& spawn_source,
      const base::FilePath& program,
      const std::vector<std::string>& arguments,
      const std::map<std::string, std::string>& environment,
      const MinijailOptions& minijail_options,
      struct std_file_descriptors std_fds);

  // Invoked when the stdout of the process |pid| is readable.
  void OnProcessStdoutReadable(pid_t pid);

  // Invoked when process |pid| exited.
  void OnProcessExited(pid_t pid, const siginfo_t& info);

  // Check the WatchedProcess struct associated with process |pid|, and invoke
  // the corresponding callback if:
  // - |exit_status| is ready when |exit_callback| is set;
  // - |exit_status| is ready and stdout pipe has been closed when
  //   |exit_with_stdout_callback| is set.
  void CheckProcessExitStateAndNotify(pid_t pid);

  // Invoked when process |pid| did not terminate within a certain timeout.
  // |kill_signal| indicates the signal used for termination. When it is set
  // to true, SIGKILL was used to terminate the process, otherwise, SIGTERM
  // was used.
  void ProcessTerminationTimeoutHandler(pid_t pid, bool kill_signal);

  // Send a termination signal to process |pid|. If |kill_signal| is set to
  // true, SIGKILL is sent, otherwise, SIGTERM is sent.  After signal is sent,
  // |pid| and timeout handler is added to |pending_termination_processes_|
  // list, to make sure process |pid| does exit in timely manner.
  bool TerminateProcess(pid_t pid, bool kill_signal);

  // Kill process |pid|. If |kill_signal| is true it will send SIGKILL,
  // otherwise it will send SIGTERM.
  // It returns true when the process was already dead or killed within
  // the timeout.
  // It returns false when the process failed to exit within the timeout
  // or the system failed to send kill singal.
  bool KillProcessWithTimeout(pid_t pid, bool kill_signal);

  // Kill process |pid| using signal |signal|.
  // The |killed| will be set true when the process was already dead.
  // It returns true when it sent the |signal| successfully or the
  // process was already dead.
  // It returns false when the system failed to send |signal|.
  bool KillProcess(pid_t pid, int signal, bool* killed);

  // Wait for process |pid| to exit. This function will check it for at most
  // |tries| times. The interval of waiting time grows exponentially from
  // |sleep_ms| and it has an |upper_bound_ms| upper bound.
  bool WaitpidWithTimeout(pid_t pid,
                          unsigned int sleep_ms,
                          unsigned int upper_bound_ms,
                          int tries);

  // Used to watch processes.
  std::unique_ptr<brillo::AsynchronousSignalHandler> async_signal_handler_;
  brillo::ProcessReaper process_reaper_;

  brillo::Minijail* minijail_;

  // Processes to watch for the caller.
  std::map<pid_t, WatchedProcess> watched_processes_;
  // Processes being terminated by us.  Use a timer to make sure process
  // does exit, log an error if it failed to exit within a specific timeout.
  std::map<pid_t, std::unique_ptr<TerminationTimeoutCallback>>
      pending_termination_processes_;

  base::WeakPtrFactory<ProcessManager> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_NET_PROCESS_MANAGER_H_
