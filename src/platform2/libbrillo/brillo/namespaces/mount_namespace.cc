// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class MountNamespace for libbrillo.

#include "brillo/namespaces/mount_namespace.h"

#include <sched.h>
#include <sys/mount.h>
#include <sys/types.h>

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/namespaces/platform.h>

namespace brillo {
MountNamespace::MountNamespace(const base::FilePath& ns_path,
                               Platform* platform)
    : ns_path_(ns_path), platform_(platform), exists_(false) {}

MountNamespace::~MountNamespace() {
  if (exists_)
    Destroy();
}

bool MountNamespace::Create() {
  if (platform_->FileSystemIsNsfs(ns_path_)) {
    LOG(ERROR) << "Mount namespace at " << ns_path_.value()
               << " already exists.";
    return false;
  }
  int fd_mounted[2];
  int fd_unshared[2];
  char byte = '\0';
  if (pipe(fd_mounted) != 0) {
    PLOG(ERROR) << "Cannot create mount signalling pipe";
    return false;
  }
  if (pipe(fd_unshared) != 0) {
    PLOG(ERROR) << "Cannot create unshare signalling pipe";
    return false;
  }
  pid_t pid = platform_->Fork();
  if (pid < 0) {
    PLOG(ERROR) << "Fork failed";
  } else if (pid == 0) {
    // Child.
    close(fd_mounted[1]);
    close(fd_unshared[0]);
    if (unshare(CLONE_NEWNS) != 0) {
      PLOG(ERROR) << "unshare(CLONE_NEWNS) failed";
      exit(1);
    }
    base::WriteFileDescriptor(fd_unshared[1], base::StringPiece(&byte, 1));
    base::ReadFromFD(fd_mounted[0], &byte, 1);
    exit(0);
  } else {
    // Parent.
    close(fd_mounted[0]);
    close(fd_unshared[1]);
    std::string proc_ns_path = base::StringPrintf("/proc/%d/ns/mnt", pid);
    bool mount_success = true;
    base::ReadFromFD(fd_unshared[0], &byte, 1);
    if (platform_->Mount(proc_ns_path, ns_path_.value(), "", MS_BIND) == 0) {
      // If the bind mount succeeds, attempt to remount it noexec.
      // TODO(betuls): Add MS_RDONLY option after the deprecation of kernel
      // v3.18. For now namespace can only be remounted with the MS_NOEXEC since
      // readonly proc fs cause boot failures on boards with kernel 3.18.
      if (platform_->Mount(proc_ns_path, ns_path_.value(), "",
                           MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC) !=
          0) {
        PLOG(ERROR)
            << "Mount(" << proc_ns_path << ", " << ns_path_.value()
            << ", MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC) failed";
        mount_success = false;
      }
    } else {
      PLOG(ERROR) << "Mount(" << proc_ns_path << ", " << ns_path_.value()
                  << ", MS_BIND) failed";
      mount_success = false;
    }
    base::WriteFileDescriptor(fd_mounted[1], base::StringPiece(&byte, 1));

    int status;
    if (platform_->Waitpid(pid, &status) < 0) {
      PLOG(ERROR) << "waitpid(" << pid << ") failed";
      return false;
    }
    if (!WIFEXITED(status)) {
      LOG(ERROR) << "Child process did not exit normally.";
    } else if (WEXITSTATUS(status) != 0) {
      LOG(ERROR) << "Child process failed.";
    } else {
      exists_ = mount_success;
    }
  }
  return exists_;
}

bool MountNamespace::Destroy() {
  if (!exists_) {
    LOG(ERROR) << "Mount namespace at " << ns_path_.value()
               << "does not exist, cannot destroy";
    return false;
  }
  bool was_busy;
  if (!platform_->Unmount(ns_path_, false /*lazy*/, &was_busy)) {
    PLOG(ERROR) << "Failed to unmount " << ns_path_.value();
    if (was_busy) {
      LOG(ERROR) << ns_path_.value().c_str() << " was busy";
    }
    // If Unmount() fails, keep the object valid by keeping |exists_|
    // set to true.
    return false;
  } else {
    VLOG(1) << "Unmounted namespace at " << ns_path_.value();
  }
  exists_ = false;
  return true;
}

}  // namespace brillo
