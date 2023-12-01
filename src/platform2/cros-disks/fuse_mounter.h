// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_FUSE_MOUNTER_H_
#define CROS_DISKS_FUSE_MOUNTER_H_

#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/strings/string_piece.h>

#include "cros-disks/metrics.h"
#include "cros-disks/mounter.h"
#include "cros-disks/sandboxed_process.h"
#include "cros-disks/user.h"

namespace brillo {
class ProcessReaper;
}  // namespace brillo

namespace cros_disks {

class Platform;
class Process;
class SandboxedProcess;

// Class for creating instances of SandboxedProcess with appropriate
// configuration.
class FUSESandboxedProcessFactory : public SandboxedProcessFactory {
 public:
  FUSESandboxedProcessFactory(
      const Platform* platform,
      SandboxedExecutable executable,
      OwnerUser run_as,
      bool has_network_access = false,
      bool kill_pid_namespace = false,
      std::vector<gid_t> supplementary_groups = {},
      std::optional<base::FilePath> mount_namespace = {});
  ~FUSESandboxedProcessFactory() override;

  // Returns pre-configured sandbox with the most essential set up. Additional
  // per-instance configuration should be done by the caller if needed.
  std::unique_ptr<SandboxedProcess> CreateSandboxedProcess() const override;

  const base::FilePath& executable() const { return executable_; }
  const OwnerUser& run_as() const { return run_as_; }

 private:
  friend class FUSESandboxedProcessFactoryTest;

  bool ConfigureSandbox(SandboxedProcess* sandbox) const;

  const Platform* const platform_;

  // Path to the FUSE daemon executable.
  const base::FilePath executable_;

  // Path to the seccomp policy configuration.
  const std::optional<base::FilePath> seccomp_policy_;

  // UID/GID to run the FUSE daemon as.
  const OwnerUser run_as_;

  // Whether to leave network accessible from the sandbox.
  const bool has_network_access_;

  // Whether to kill the PID namespace when unmounting the FUSE mount point.
  const bool kill_pid_namespace_;

  // Additional groups to associate with the FUSE daemon process.
  const std::vector<gid_t> supplementary_groups_;

  // Path identifying the mount namespace to use.
  const std::optional<base::FilePath> mount_namespace_;
};

// Uprivileged mounting of any FUSE filesystem. Filesystem-specific set up
// and sandboxing is to be done in a subclass.
class FUSEMounter : public Mounter {
 public:
  struct Config {
    // Metrics object and name used to record the FUSE launcher exit code.
    Metrics* const metrics = nullptr;
    std::string metrics_name;

    // Set of FUSE launcher exit codes that are interpreted as
    // MountError::kNeedPassword.
    std::vector<int> password_needed_exit_codes;

    bool nosymfollow = true;
    bool read_only = false;
  };

  FUSEMounter(const Platform* platform,
              brillo::ProcessReaper* process_reaper,
              std::string filesystem_type,
              Config config);
  FUSEMounter(const FUSEMounter&) = delete;
  FUSEMounter& operator=(const FUSEMounter&) = delete;
  ~FUSEMounter() override;

  const Platform* platform() const { return platform_; }
  brillo::ProcessReaper* process_reaper() const { return process_reaper_; }
  std::string filesystem_type() const { return filesystem_type_; }

  // Mounter overrides:
  std::unique_ptr<MountPoint> Mount(const std::string& source,
                                    const base::FilePath& target_path,
                                    std::vector<std::string> params,
                                    MountError* error) const final;

 protected:
  // Is this FUSE mounter password-aware?
  bool AcceptsPassword() const {
    return !config_.password_needed_exit_codes.empty();
  }

  // Performs necessary set up and makes a SandboxedProcess ready to be
  // launched to serve a mount. The returned instance will have one more
  // last argument added to indicate the FUSE mount path according to
  // fusermount's conventions, so implementation doesn't have to do this,
  // |target_path| is purely informational.
  virtual std::unique_ptr<SandboxedProcess> PrepareSandbox(
      const std::string& source,
      const base::FilePath& target_path,
      std::vector<std::string> params,
      MountError* error) const = 0;

 private:
  // Performs necessary set up and launches FUSE daemon that communicates to
  // FUSE kernel layer via the |fuse_file|. Returns the Process holding the FUSE
  // daemon.
  std::unique_ptr<SandboxedProcess> StartDaemon(
      base::File fuse_file,
      const std::string& source,
      const base::FilePath& target_path,
      std::vector<std::string> params,
      MountError* error) const;

 private:
  const Platform* const platform_;
  brillo::ProcessReaper* const process_reaper_;
  const std::string filesystem_type_;
  const Config config_;
};

// A convenience class to tie FUSE mounter with a sandbox configuration.
class FUSEMounterHelper : public FUSEMounter {
 public:
  FUSEMounterHelper(const Platform* platform,
                    brillo::ProcessReaper* process_reaper,
                    std::string filesystem_type,
                    bool nosymfollow,
                    const SandboxedProcessFactory* sandbox_factory);
  FUSEMounterHelper(const FUSEMounterHelper&) = delete;
  FUSEMounterHelper& operator=(const FUSEMounterHelper&) = delete;
  ~FUSEMounterHelper() override;

 protected:
  const SandboxedProcessFactory* sandbox_factory() const {
    return sandbox_factory_;
  }

  // FUSEMounter overrides:
  std::unique_ptr<SandboxedProcess> PrepareSandbox(
      const std::string& source,
      const base::FilePath& target_path,
      std::vector<std::string> params,
      MountError* error) const final;

  virtual MountError ConfigureSandbox(const std::string& source,
                                      const base::FilePath& target_path,
                                      std::vector<std::string> params,
                                      SandboxedProcess* sandbox) const = 0;

 private:
  const SandboxedProcessFactory* const sandbox_factory_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_FUSE_MOUNTER_H_
