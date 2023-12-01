// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Platform for libbrillo.

#include "brillo/namespaces/platform.h"

#include <errno.h>
#include <linux/magic.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>

#include <base/files/file_path.h>
#include <base/logging.h>

using base::FilePath;

namespace brillo {

Platform::Platform() {}

Platform::~Platform() {}

bool Platform::FileSystemIsNsfs(const FilePath& ns_path) {
  struct statfs buff;
  if (statfs(ns_path.value().c_str(), &buff) < 0) {
    PLOG(ERROR) << "Statfs() error for " << ns_path.value();
    return false;
  }
  if ((uint64_t)buff.f_type == NSFS_MAGIC) {
    return true;
  }
  return false;
}

bool Platform::Unmount(const FilePath& path, bool lazy, bool* was_busy) {
  int flags = 0;
  if (lazy) {
    flags = MNT_DETACH;
  }
  if (umount2(path.value().c_str(), flags) != 0) {
    if (was_busy) {
      *was_busy = (errno == EBUSY);
    }
    return false;
  }
  if (was_busy) {
    *was_busy = false;
  }
  return true;
}

int Platform::Mount(const std::string& source,
                    const std::string& target,
                    const std::string& fs_type,
                    uint64_t mount_flags,
                    const void* data) {
  return mount(source.c_str(), target.c_str(), fs_type.c_str(), mount_flags,
               data);
}

pid_t Platform::Fork() {
  return fork();
}

pid_t Platform::Waitpid(pid_t pid, int* status) {
  return waitpid(pid, status, 0);
}

}  // namespace brillo
