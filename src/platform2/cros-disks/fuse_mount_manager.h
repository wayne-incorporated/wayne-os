// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_FUSE_MOUNT_MANAGER_H_
#define CROS_DISKS_FUSE_MOUNT_MANAGER_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>

#include "cros-disks/mount_manager.h"

namespace cros_disks {

class Mounter;

// Implementation of MountManager for mounting arbitrary FUSE-based filesystems.
// It essentially does dispatching of mount requests to individual FUSE helpers.
class FUSEMountManager : public MountManager {
 public:
  // |mount_root| - where mount points go.
  // |working_dirs_root| - where temporary working directories go.
  FUSEMountManager(const std::string& mount_root,
                   const std::string& working_dirs_root,
                   Platform* platform,
                   Metrics* metrics,
                   brillo::ProcessReaper* process_reaper);
  FUSEMountManager(const FUSEMountManager&) = delete;
  FUSEMountManager& operator=(const FUSEMountManager&) = delete;

  ~FUSEMountManager() override;

  bool Initialize() override;

  // Whether we know about FUSE driver able to handle this source. Note that
  // source doesn't have to be an actual file or path, it could be anything
  // identifying FUSE module and what instance to mount.
  bool CanMount(const std::string& source) const override;

  MountSourceType GetMountSourceType() const final {
    return MOUNT_SOURCE_NETWORK_STORAGE;
  }

 protected:
  // Mounts |source| to |mount_path| as |fuse_type| with |options|.
  // |fuse_type| can be used to specify the type of |source|.
  // If |fuse_type| is an empty string, the type is determined based on the
  // format of the |source|. The underlying mounter may append their own mount
  // options to |options|.
  std::unique_ptr<MountPoint> DoMount(const std::string& source,
                                      const std::string& fuse_type,
                                      const std::vector<std::string>& options,
                                      const base::FilePath& mount_path,
                                      MountError* error) override;

  // Returns a suggested mount path for a source.
  std::string SuggestMountPath(const std::string& source) const override;

  void RegisterHelper(std::unique_ptr<Mounter> mounter);

 private:
  FRIEND_TEST(FUSEMountManagerTest, SuggestMountPath);
  friend class FUSEMountManagerTest;

  std::vector<std::unique_ptr<Mounter>> helpers_;
  const std::string working_dirs_root_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_FUSE_MOUNT_MANAGER_H_
