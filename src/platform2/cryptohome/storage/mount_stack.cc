// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/mount_stack.h"

#include <algorithm>
#include <base/files/file_path.h>
#include <base/logging.h>

using base::FilePath;

namespace cryptohome {

MountStack::MountInfo::MountInfo(const FilePath& src, const FilePath& dest)
    : src(src), dest(dest) {}

MountStack::MountStack() {}

MountStack::~MountStack() {
  if (!mounts_.empty()) {
    LOG(ERROR) << "MountStack destroyed with " << mounts_.size() << " mounts.";
    for (const auto& it : mounts_)
      LOG(ERROR) << "  " << it.src.value() << " -> " << it.dest.value();
  }
}

void MountStack::Push(const FilePath& src, const FilePath& dest) {
  mounts_.push_back(MountInfo(src, dest));
}

bool MountStack::Pop(FilePath* src_out, FilePath* dest_out) {
  if (mounts_.empty())
    return false;

  const MountInfo& info = mounts_.back();
  *src_out = info.src;
  *dest_out = info.dest;
  mounts_.pop_back();
  return true;
}

bool MountStack::ContainsDest(const FilePath& dest) const {
  for (const auto& info : mounts_) {
    if (info.dest == dest)
      return true;
  }
  return false;
}

std::vector<base::FilePath> MountStack::MountDestinations() const {
  std::vector<base::FilePath> res;
  for (const auto& mount : mounts_) {
    res.push_back(mount.dest);
  }
  return res;
}

}  // namespace cryptohome
