// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_OBB_MOUNTER_MOUNT_OBB_FUSE_MAIN_H_
#define ARC_CONTAINER_OBB_MOUNTER_MOUNT_OBB_FUSE_MAIN_H_

#include <string>
// Top-level function in mount obb to call fuse_main().
int mount_obb_fuse_main(const std::string& file_system_name,
                        const std::string& obb_filename,
                        const std::string& mount_path,
                        const std::string& owner_uid,
                        const std::string& owner_gid);

#endif  // ARC_CONTAINER_OBB_MOUNTER_MOUNT_OBB_FUSE_MAIN_H_
