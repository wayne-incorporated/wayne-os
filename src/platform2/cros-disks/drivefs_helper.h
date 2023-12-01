// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DRIVEFS_HELPER_H_
#define CROS_DISKS_DRIVEFS_HELPER_H_

#include <memory>
#include <string>
#include <vector>

#include "cros-disks/fuse_mounter.h"

namespace cros_disks {

class Platform;

// A mounter for DriveFS.
//
// DriveFS URIs are of the form:
// drivefs://identity
//
// |identity| is an opaque string. In particular it's a string representation of
// a base::UnguessableToken, used to lookup a pending DriveFS mount in Chrome.
//
// The datadir option is required. It is the path DriveFS should use for its
// data. It must be an absolute path without parent directory references.
class DrivefsHelper : public FUSEMounterHelper {
 public:
  DrivefsHelper(const Platform* platform,
                brillo::ProcessReaper* process_reaper);
  DrivefsHelper(const DrivefsHelper&) = delete;
  DrivefsHelper& operator=(const DrivefsHelper&) = delete;

  ~DrivefsHelper() override;

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

  friend class DrivefsHelperTest;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DRIVEFS_HELPER_H_
