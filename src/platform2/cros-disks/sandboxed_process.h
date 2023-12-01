// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_SANDBOXED_PROCESS_H_
#define CROS_DISKS_SANDBOXED_PROCESS_H_

#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/containers/span.h>
#include <base/files/file.h>
#include <base/functional/callback.h>

#include "cros-disks/process.h"
#include "cros-disks/sandboxed_init.h"

struct minijail;

namespace cros_disks {

class SandboxedProcess : public Process {
 public:
  SandboxedProcess();
  SandboxedProcess(const SandboxedProcess&) = delete;
  SandboxedProcess& operator=(const SandboxedProcess&) = delete;

  ~SandboxedProcess() override;

  bool KillPidNamespace() override;

  // Loads the seccomp filters from |policy_file|. The calling process will be
  // aborted if |policy_file| does not exist, cannot be read or is malformed.
  void LoadSeccompFilterPolicy(const std::string& policy_file);

  // Puts the process to be sandboxed in a new cgroup namespace.
  void NewCgroupNamespace();

  // Puts the process to be sandboxed in a new IPC namespace.
  void NewIpcNamespace();

  // Puts the process to be sandboxed in a new mount namespace.
  void NewMountNamespace();

  // Puts the process to be sandboxed in an existing mount namespace.
  // Can be combined with NewMountNamespace() above: the process will first
  // enter the existing namespace and then unshare a new child namespace.
  void EnterExistingMountNamespace(const std::string& ns_path);

  // Puts the process to be sandboxed in a new network namespace.
  void NewNetworkNamespace();

  // Puts the process to be sandboxed in a new PID namespace.
  void NewPidNamespace();

  // Assuming the process is sandboxed in a new mount namespace, some essential
  // mountpoints like / and /proc are being set up.
  bool SetUpMinimalMounts();

  // Maps a file or a folder into process' mount namespace.
  bool BindMount(const std::string& from,
                 const std::string& to,
                 bool writeable,
                 bool recursive);

  // Mounts source to the specified folder in the new mount namespace.
  bool Mount(const std::string& src,
             const std::string& to,
             const std::string& type,
             const char* data);

  // Makes the process to call pivot_root for an empty /.
  bool EnterPivotRoot();

  // Sets the no_new_privs bit.
  void SetNoNewPrivileges();

  // Sets the process capabilities of the process to be sandboxed.
  void SetCapabilities(uint64_t capabilities);

  // Sets the primary group ID of the process to be sandboxed.
  void SetGroupId(gid_t group_id);

  // Sets the user ID of the process to be sandboxed.
  void SetUserId(uid_t user_id);

  // Sets supplementary group IDs of the process to be sandboxed.
  void SetSupplementaryGroupIds(base::span<const gid_t> gids);

  // Adds the minijail to |cgroup|.
  bool AddToCgroup(const std::string& cgroup);

  // Preserves the given file descriptor to still be available in the sandboxed
  // process.
  void PreserveFile(int fd);

  // Sets the flag that will simulate progress by delaying the execution of the
  // sandboxed program by 10 seconds.
  //
  // Precondition: NewPidNamespace() was called.
  void SimulateProgressForTesting() {
    DCHECK(use_pid_namespace_);
    simulate_progress_for_testing_ = true;
  }

  // Should the destruction of this SandboxedProcess trigger the destruction of
  // the PID namespace it manages and all the process that are still running in
  // it?
  void SetKillPidNamespace(const bool kill) { kill_pid_namespace_ = kill; }

 protected:
  // Process overrides:
  pid_t StartImpl(base::ScopedFD in_fd, base::ScopedFD out_fd) override;
  int WaitImpl() override;
  int WaitNonBlockingImpl() override;

  // Minijail object.
  minijail* jail_;

  // Does this SandboxedProcess use a PID namespace?
  bool use_pid_namespace_ = false;

  // Whether the destruction of this SandboxedProcess triggers the destruction
  // of the PID namespace and all the process that are still running in it.
  bool kill_pid_namespace_ = false;

  // Should simulate progress and delay the start of the process for testing?
  bool simulate_progress_for_testing_ = false;

  // Write end of the pipe used to terminate the init process inside the PID
  // namespace. This end of the pipe is closed when the SandboxedProcess
  // instance is destroyed, generating a SIGIO in the child init process, which
  // triggers termination of init and all its nested children. Only used when
  // |use_pid_namespace_| is true.
  base::ScopedFD termination_fd_;
};

// Interface for creating preconfigured instances of |SandboxedProcess|.
class SandboxedProcessFactory {
 public:
  SandboxedProcessFactory() = default;
  virtual ~SandboxedProcessFactory() = default;
  virtual std::unique_ptr<SandboxedProcess> CreateSandboxedProcess() const = 0;
};

// Ties executable with the corresponding seccomp policy configuration.
struct SandboxedExecutable {
  base::FilePath executable;
  std::optional<base::FilePath> seccomp_policy = {};
};

// Fake SandboxedProcess for testing. Doesn't launch any actual process.
class FakeSandboxedProcess : public SandboxedProcess {
 public:
  virtual int OnProcessLaunch(const std::vector<std::string>& argv);

  bool GetSimulateProgressForTesting() const {
    return simulate_progress_for_testing_;
  }

 private:
  pid_t StartImpl(base::ScopedFD, base::ScopedFD) final;
  int WaitImpl() final;
  int WaitNonBlockingImpl() final;

  std::optional<int> ret_code_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_SANDBOXED_PROCESS_H_
