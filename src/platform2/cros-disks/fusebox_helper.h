// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_FUSEBOX_HELPER_H_
#define CROS_DISKS_FUSEBOX_HELPER_H_

#include "cros-disks/fuse_mounter.h"

#include <string>
#include <vector>

namespace cros_disks {

struct OwnerUser;

// FuseBox "fusebox://" URI mounter.
class FuseBoxHelper : public FUSEMounterHelper {
 public:
  FuseBoxHelper(const Platform* platform, brillo::ProcessReaper* reaper);

  FuseBoxHelper(const FuseBoxHelper&) = delete;
  FuseBoxHelper& operator=(const FuseBoxHelper&) = delete;

  ~FuseBoxHelper() override;

  OwnerUser ResolveFuseBoxOwnerUser(const Platform* platform) const;

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

  friend class FuseBoxHelperTest;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_FUSEBOX_HELPER_H_
