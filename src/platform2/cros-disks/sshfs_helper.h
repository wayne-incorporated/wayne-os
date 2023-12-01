// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_SSHFS_HELPER_H_
#define CROS_DISKS_SSHFS_HELPER_H_

#include <memory>
#include <string>
#include <vector>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/sandboxed_process.h"
#include "cros-disks/uri.h"

namespace cros_disks {

// Invokes sshfs to provide access to files over SFTP protocol. Supports
// sshfs://... URIs, which behaves per usual sftp-over-ssh, and
// sftp://$cid:$port which will instead skip ssh and instead connect directly to
// an already-running sftp-server instance on port $port inside the VM
// identified by $cid.
class SshfsHelper : public FUSEMounterHelper {
 public:
  SshfsHelper(const Platform* platform,
              brillo::ProcessReaper* process_reaper,
              base::FilePath working_dir);
  SshfsHelper(const SshfsHelper&) = delete;
  SshfsHelper& operator=(const SshfsHelper&) = delete;

  ~SshfsHelper() override;

  bool CanMount(const std::string& source,
                const std::vector<std::string>& params,
                base::FilePath* suggested_name) const override;

 protected:
  MountError ConfigureSandbox(const std::string& source,
                              const base::FilePath& target_path,
                              std::vector<std::string> params,
                              SandboxedProcess* sandbox) const override;

 private:
  MountError ConfigureSandboxSshfs(const Uri& source,
                                   std::vector<std::string> params,
                                   SandboxedProcess* sandbox) const;
  MountError ConfigureSandboxSftpVsock(const Uri& source,
                                       SandboxedProcess* sandbox) const;
  const FUSESandboxedProcessFactory sandbox_factory_;
  const base::FilePath working_dir_;

  friend class SshfsHelperTest;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_SSHFS_HELPER_H_
