// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_OBB_MOUNTER_MOUNT_H_
#define ARC_CONTAINER_OBB_MOUNTER_MOUNT_H_

#include <sys/types.h>

#include <string>

namespace arc {
namespace obb_mounter {

// Mounts the specified OBB file.
bool MountObb(const std::string& obb_file,
              const std::string& mount_path,
              gid_t owner_gid);

// Unmounts the OBB file mounted at the specified path.
bool UnmountObb(const std::string& mount_path);

}  // namespace obb_mounter
}  // namespace arc

#endif  // ARC_CONTAINER_OBB_MOUNTER_MOUNT_H_
