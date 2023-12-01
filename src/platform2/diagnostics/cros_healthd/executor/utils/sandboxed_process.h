// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_SANDBOXED_PROCESS_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_SANDBOXED_PROCESS_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <brillo/process/process.h>

namespace diagnostics {

inline constexpr char kCrosHealthdSandboxUser[] = "cros_healthd";
inline constexpr char kMinijailBinary[] = "/sbin/minijail0";
inline constexpr char kSeccompPolicyDirectory[] = "/usr/share/policy/";

// SandboxOption is used to customized minijail configuration. Default to
// passing without option for highest security.
// TODO(b/287409040): put options into |SandboxedProcess::Options|.
enum SandboxOption {
  // Do not enter a new network namespace for minijail.
  NO_ENTER_NETWORK_NAMESPACE = 1 << 0,
  // Mount /run/imageloader for accessing DLC.
  MOUNT_DLC = 1 << 1,
};

// Runs a command under minijail.
//
// The arguments:
// * |command|: The command to be run.
// * |seccomp_file|: The filename of the seccomp policy file under the default
//     policy directory(/usr/share/policy/).
// * |options|: Extra options for minijail. See comments of the class |Options|.
class SandboxedProcess : public brillo::ProcessImpl {
 public:
  // The options
  // * |user|: The user to run the command. Default to
  //     |kCrosHealthdSandboxUser|.
  // * |capabilities_mask|: The capabilities mask. See linux headers
  //     "uapi/linux/capability.h". Default to |0| (no capability).
  // * |readonly_mount_points|: The paths to be mounted readonly. If a path
  //     doesn't exist it is ignored. Default to |{}|.
  // * |writable_mount_points|: The paths to be mounted writable. All the paths
  //     must exist, otherwise the process will fail to be run. Default to |{}|.
  // * |sandbox_option|: Open sandbox without certain flags, use bit-wise
  //     options from SandboxOption to customize. Default to 0 for maximum
  //     security.
  struct Options {
    std::string user = kCrosHealthdSandboxUser;
    uint64_t capabilities_mask = 0;
    std::vector<base::FilePath> readonly_mount_points;
    std::vector<base::FilePath> writable_mount_points;
    uint32_t sandbox_option = 0;
  };

  SandboxedProcess(const std::vector<std::string>& command,
                   const std::string& seccomp_filename,
                   const Options& options);
  SandboxedProcess(const SandboxedProcess&) = delete;
  SandboxedProcess& operator=(const SandboxedProcess&) = delete;

  ~SandboxedProcess() override;

  // Overrides brillo::ProcessImpl. Adds arguments to command. This won't affect
  // the sandbox arguments.
  void AddArg(const std::string& arg) override;

  // Overrides brillo::ProcessImpl.
  bool Start() override;
  bool Kill(int signal, int timeout) override;
  void Reset(pid_t new_pid) override;

  // First try to use SIGTERM to kill jailed process to prevent minijail from
  // printing error message about child receiving SIGKILL. This method may block
  // for a few seconds. Returns the exit status of minijail process or -1 on
  // error.
  int KillAndWaitSandboxProcess();

 protected:
  SandboxedProcess();

 private:
  // Prepares some arguments which need to be handled before use.
  virtual void PrepareSandboxArguments();

  // Adds argument to process. For mocking.
  virtual void BrilloProcessAddArg(const std::string& arg);

  // Adds argument to process. For mocking.
  virtual bool BrilloProcessStart();

  // Checks if a file exist. For mocking.
  virtual bool IsPathExists(const base::FilePath& path) const;

  // Kill the jailed process and wait for the minijail process. Return the exit
  // status of the minijail process on success, or -1 on error or timeout.
  int KillJailedProcess(int signal, base::TimeDelta timeout);

  // The arguments of minijail.
  std::vector<std::string> sandbox_arguments_;
  // The command to run by minijail.
  std::vector<std::string> command_;
  // The paths to be mounted readonly.
  std::vector<base::FilePath> readonly_mount_points_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_SANDBOXED_PROCESS_H_
