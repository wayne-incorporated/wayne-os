// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/appfuse/appfuse_mount.h"

#include <fcntl.h>
#include <sys/mount.h>

#include <utility>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/files/file_util.h>

namespace arc {
namespace appfuse {

AppfuseMount::AppfuseMount(const base::FilePath& mount_root,
                           uid_t uid,
                           int mount_id,
                           Delegate* delegate)
    : mount_root_(mount_root),
      uid_(uid),
      mount_id_(mount_id),
      delegate_(delegate),
      mount_point_(
          mount_root.Append(base::StringPrintf("%d_%d", uid, mount_id))),
      weak_ptr_factory_(this) {}

AppfuseMount::~AppfuseMount() {
  Unmount();
}

base::ScopedFD AppfuseMount::Mount() {
  // Create the mount point directory.
  if (!base::CreateDirectory(mount_point_)) {
    PLOG(ERROR) << "Failed to prepare directory " << mount_point_.value();
    return base::ScopedFD();
  }

  // Open device FD.
  base::ScopedFD dev_fuse(HANDLE_EINTR(open("/dev/fuse", O_RDWR | O_CLOEXEC)));
  if (!dev_fuse.is_valid()) {
    PLOG(ERROR) << "Failed to open /dev/fuse";
    return base::ScopedFD();
  }
  // An Android app runs with its own UID and GID whose values are the same.
  const gid_t gid = uid_;
  const auto opts = base::StringPrintf(
      "fd=%i,"
      "rootmode=40000,"
      "default_permissions,"
      "allow_other,"
      "user_id=%d,group_id=%d,"
      "context=\"u:object_r:app_fuse_file:s0\","
      "fscontext=u:object_r:app_fusefs:s0",
      dev_fuse.get(), uid_, gid);

  if (mount("/dev/fuse", mount_point_.value().c_str(), "fuse",
            MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, opts.c_str()) != 0) {
    PLOG(ERROR) << "Failed to mount " << mount_point_.value();
    return base::ScopedFD();
  }
  // OnDataFilterStopped will be called when the data filter stops on an error.
  data_filter_.set_on_stopped_callback(base::BindOnce(
      &AppfuseMount::OnDataFilterStopped, weak_ptr_factory_.GetWeakPtr()));
  return data_filter_.Start(std::move(dev_fuse));
}

bool AppfuseMount::Unmount() {
  if (umount2(mount_point_.value().c_str(), UMOUNT_NOFOLLOW | MNT_DETACH) !=
          0 &&
      errno != EINVAL && errno != ENOENT) {
    PLOG(ERROR) << "Failed to unmount " << mount_point_.value();
    return false;
  }
  if (!brillo::DeletePathRecursively(mount_point_)) {
    PLOG(ERROR) << "Failed to delete " << mount_point_.value();
    return false;
  }
  return true;
}

base::ScopedFD AppfuseMount::OpenFile(int file_id, int flags) {
  base::FilePath path = mount_point_.Append(base::StringPrintf("%d", file_id));
  return base::ScopedFD(HANDLE_EINTR(open(path.value().c_str(), flags)));
}

void AppfuseMount::OnDataFilterStopped() {
  delegate_->OnAppfuseMountAborted(this);
}

}  // namespace appfuse
}  // namespace arc
