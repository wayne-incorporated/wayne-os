// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_MAITRED_INIT_H_
#define VM_TOOLS_MAITRED_INIT_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/threading/thread.h>

namespace vm_tools {
namespace maitred {

// Given the contents of /etc/hostname, return the hostname to set, or an
// empty string on failure.
std::string ParseHostname(const std::string& etc_hostname_contents);

// Encapsulates all the functionality for which maitred is responsible when it
// runs as pid 1 on a VM.
class Init final {
 public:
  // The reason why a process exited.
  enum class ProcessStatus {
    // Process is in an unknown state.
    UNKNOWN,

    // Process exited.
    EXITED,

    // Killed by a signal.
    SIGNALED,

    // Launched but may or may not have exited yet.
    LAUNCHED,

    // One or more setup steps failed and the process did not launch.
    FAILED,
  };

  // Information about a process launch.
  struct ProcessLaunchInfo {
    ProcessLaunchInfo() = default;

    // Current status of the process.
    ProcessStatus status = ProcessStatus::UNKNOWN;

    // If |status| is EXITED, then this will hold the exit status.  If |status|
    // is SIGNALED, then this will hold the signal number that killed the
    // process.  Otherwise this value is undefined.
    int32_t code = 0;

    // Output from the process's stdout handle.
    // Only filled when spawned with |wait_for_exit| = true and |use_console| =
    // false.
    std::string output;

    // If the spawned process potentially produced more than the maximum allowed
    // output, |output_truncated| will be set to true.
    bool output_truncated;
  };

  // Creates a new instance of this class and performs various bits of early
  // setup up like mounting file systems, creating directories, and setting
  // up signal handlers.
  static std::unique_ptr<Init> Create(bool maitred_is_pid1);
  ~Init();

  // Spawn a process with the given argv and environment.  |argv[0]| must be
  // the full path to the program or the name of a program found in PATH.  If
  // |wait_for_exit| is true, then wait for the spawned process to exit and
  // fill in |launch_info| with the information about the process's exit.
  bool Spawn(std::vector<std::string> argv,
             std::map<std::string, std::string> env,
             bool respawn,
             bool use_console,
             bool wait_for_exit,
             ProcessLaunchInfo* launch_info,
             std::optional<base::OnceCallback<void(ProcessStatus, int)>>
                 exit_cb = std::nullopt);

  // Shuts down the system, killing all child processes first with SIGTERM and
  // finally with SIGKILL.
  void Shutdown();

 private:
  explicit Init(bool maitred_is_pid1);
  Init(const Init&) = delete;
  Init& operator=(const Init&) = delete;

  // Subroutine to setup resource limits. For more details of resource limits,
  // see man page of setrlimits and sysctl.
  bool SetupResourceLimit();

  bool Setup();

  // Worker that lives on a separate thread and is responsible for actually
  // doing all the work.
  class Worker;
  std::unique_ptr<Worker> worker_;

  // The actual worker thread.
  base::Thread worker_thread_{"init worker thread"};

  // Check at runtime if maitred is pid 1, true is maitred is pid 1.
  bool maitred_is_pid1_;
};

}  //  namespace maitred
}  // namespace vm_tools

#endif  // VM_TOOLS_MAITRED_INIT_H_
