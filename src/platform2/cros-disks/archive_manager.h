// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_ARCHIVE_MANAGER_H_
#define CROS_DISKS_ARCHIVE_MANAGER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <brillo/scoped_mount_namespace.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/mount_manager.h"
#include "cros-disks/mount_options.h"

namespace cros_disks {

class ArchiveMounter;

// A derived class of MountManager for mounting archive files as a virtual
// filesystem.
class ArchiveManager : public MountManager {
 public:
  ArchiveManager(const std::string& mount_root,
                 Platform* platform,
                 Metrics* metrics,
                 brillo::ProcessReaper* process_reaper);
  ArchiveManager(const ArchiveManager&) = delete;
  ArchiveManager& operator=(const ArchiveManager&) = delete;

  ~ArchiveManager() override;

  // MountManager overrides
  bool Initialize() override;

  MountSourceType GetMountSourceType() const final {
    return MOUNT_SOURCE_ARCHIVE;
  }

  bool ResolvePath(const std::string& path, std::string* real_path) final;

  std::string SuggestMountPath(const std::string& source_path) const final;

  // Checks if the given file path is in an allowed location to be mounted as an
  // archive. The following paths can be mounted:
  //
  //     /home/chronos/u-<user-id>/MyFiles/...<file>
  //     /media/archive/<dir>/...<file>
  //     /media/fuse/<dir>/...<file>
  //     /media/removable/<dir>/...<file>
  //     /run/arc/sdcard/write/emulated/0/<dir>/...<file>
  static bool IsInAllowedFolder(const std::string& source_path);

  // Gets a list of supplementary group IDs the FUSE mounter program should run
  // with in order to access files in all the required locations.
  std::vector<gid_t> GetSupplementaryGroups() const;

  bool CanMount(const std::string& source_path) const override;

 protected:
  std::unique_ptr<MountPoint> DoMount(const std::string& source_path,
                                      const std::string& filesystem_type,
                                      const std::vector<std::string>& options,
                                      const base::FilePath& mount_path,
                                      MountError* error) override;

 private:
  friend class ArchiveManagerUnderTest;

  std::unique_ptr<FUSESandboxedProcessFactory> CreateSandboxFactory(
      SandboxedExecutable executable, const std::string& user_name) const;

  std::vector<std::unique_ptr<ArchiveMounter>> mounters_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_ARCHIVE_MANAGER_H_
