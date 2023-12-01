// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_EXECUTOR_MOUNT_H_
#define RMAD_EXECUTOR_MOUNT_H_

#include <memory>
#include <set>
#include <string>

#include <base/files/file_path.h>

#include "rmad/udev/udev_utils.h"

namespace rmad {

class Mount {
 public:
  // Empty mount.
  Mount();
  // Mount with specified device path and mount point.
  Mount(const base::FilePath& device_path,
        const base::FilePath& mount_point,
        const std::string& fs_type,
        bool read_only);
  // Used to inject |udev_utils| for testing.
  Mount(const base::FilePath& device_path,
        const base::FilePath& mount_point,
        const std::string& fs_type,
        bool read_only,
        std::unique_ptr<UdevUtils> udev_utils);
  // Make the class non-copyable but moveable.
  Mount(const Mount& mount) = delete;
  Mount& operator=(const Mount& mount) = delete;
  Mount(Mount&& mount);
  Mount& operator=(Mount&& mount);

  ~Mount();  // Unmount.

  bool IsValid() const { return valid_; }

 private:
  bool AttemptMount(const base::FilePath& device_path,
                    const base::FilePath& mount_point,
                    const std::string& fs_type,
                    bool read_only);
  bool VerifyMountPoint(const base::FilePath& mount_point);

  base::FilePath mount_point_;
  bool valid_;
  std::unique_ptr<UdevUtils> udev_utils_;
};

}  // namespace rmad

#endif  // RMAD_EXECUTOR_MOUNT_H_
