// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/obb-mounter/mount.h"

#include <mntent.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/files/file_util.h>

namespace arc {
namespace obb_mounter {

namespace {

const int kRootUid = 0;
const int kUidNamespaceOffset = 655360;
const int kGidNamespaceOffset = 655360;

const char kMountObbExecutableName[] = "mount-obb";

bool IsObbMountedAt(const std::string& mount_path) {
  std::unique_ptr<FILE, int (*)(FILE*)> fp(setmntent("/proc/mounts", "r"),
                                           endmntent);
  if (!fp) {
    LOG(ERROR) << "setmntent failed.";
    return false;
  }
  while (mntent* mentry = getmntent(fp.get())) {
    if (strcmp(kMountObbExecutableName, mentry->mnt_fsname) == 0 &&
        mount_path == mentry->mnt_dir) {
      return true;
    }
  }
  return false;
}

}  // namespace

bool MountObb(const std::string& obb_file,
              const std::string& mount_path,
              gid_t owner_gid) {
  if (IsObbMountedAt(mount_path)) {
    LOG(ERROR) << mount_path << " is already occupied.";
    return false;
  }
  // Make destination directory.
  if (!base::CreateDirectory(base::FilePath(mount_path))) {
    PLOG(ERROR) << "Failed to create the destination directory.";
    return false;
  }
  // Add UID namespace offsets.
  pid_t owner_uid = kRootUid + kUidNamespaceOffset;
  owner_gid += kGidNamespaceOffset;
  if (owner_gid < kGidNamespaceOffset) {
    LOG(ERROR) << "Invalid owner_gid value: " << owner_gid;
    return false;
  }
  // Run mount-obb.
  std::string owner_uid_string = base::NumberToString(owner_uid);
  std::string owner_gid_string = base::NumberToString(owner_gid);
  pid_t pid = fork();
  if (pid == -1) {
    PLOG(ERROR) << "fork failed";
    return false;
  }
  if (pid == 0) {
    const char* argv[] = {
        kMountObbExecutableName,  obb_file.c_str(),         mount_path.c_str(),
        owner_uid_string.c_str(), owner_gid_string.c_str(), nullptr,
    };
    execvp(argv[0], const_cast<char**>(argv));
    _exit(EXIT_FAILURE);
  }
  // Wait for mount-obb.
  const int kMaxRetries = 5000;
  const int kIntervalMicroseconds = 1000;
  for (int i = 0; i < kMaxRetries; ++i) {
    // Check if mount-obb is still running.
    if (waitpid(pid, nullptr, WNOHANG) != 0) {
      LOG(ERROR) << "mount-obb encounted an error and exited.";
      return false;
    }
    // Try to find the new mount point.
    if (IsObbMountedAt(mount_path)) {
      return true;
    }
    // Wait for a while.
    usleep(kIntervalMicroseconds);
  }
  LOG(ERROR) << "Mount timeout.";
  // Note: Because signal(SIGCHLD, SIG_IGN) is called in main(), here we may end
  // up killing a wrong process with the same PID (i.e. the child process exited
  // and the same PID was assigned to a new process). However, as long as we are
  // in our own PID namespace and no fork() happens on any threads other than
  // this one, we don't have to worry about it.
  kill(pid, SIGKILL);
  return false;
}

bool UnmountObb(const std::string& mount_path) {
  if (!IsObbMountedAt(mount_path)) {
    LOG(ERROR) << "OBB not mounted at " << mount_path;
    return false;
  }
  // Note: This doesn't match with Vold's corresponding behavior where it tries
  // to kill all processes which are accessing the file system being unmounted.
  if (umount2(mount_path.c_str(), MNT_DETACH)) {
    PLOG(ERROR) << "umount failed";
    return false;
  }
  if (!brillo::DeletePathRecursively(base::FilePath(mount_path))) {
    LOG(ERROR) << "Failed to delete the destination directory.";
    return false;
  }
  return true;
}

}  // namespace obb_mounter
}  // namespace arc
