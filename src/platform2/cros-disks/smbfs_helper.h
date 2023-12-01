// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_SMBFS_HELPER_H_
#define CROS_DISKS_SMBFS_HELPER_H_

#include <memory>
#include <string>
#include <vector>

#include "cros-disks/fuse_mounter.h"

namespace cros_disks {

class Platform;

// A helper for mounting SmbFs.
//
// SmbFs URIs are of the form:
// smbfs://mojo_id
//
// |mojo_id| is an opaque string, which is the string representation of a
// base::UnguessableToken created by calling base::UnguessableToken::ToString().
// It is used to bootstrap a Mojo IPC connection to Chrome.
class SmbfsHelper : public FUSEMounterHelper {
 public:
  SmbfsHelper(const Platform* platform, brillo::ProcessReaper* process_reaper);
  SmbfsHelper(const SmbfsHelper&) = delete;
  SmbfsHelper& operator=(const SmbfsHelper&) = delete;

  ~SmbfsHelper() override;

  bool CanMount(const std::string& source,
                const std::vector<std::string>& params,
                base::FilePath* suggested_name) const override;

 protected:
  MountError ConfigureSandbox(const std::string& source,
                              const base::FilePath& target_path,
                              std::vector<std::string> params,
                              SandboxedProcess* sandbox) const override;

 private:
  const FUSESandboxedProcessFactory sandbox_factory_;

  friend class SmbfsHelperTest;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_SMBFS_HELPER_H_
