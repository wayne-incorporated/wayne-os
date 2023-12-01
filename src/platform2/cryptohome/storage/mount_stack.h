// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_MOUNT_STACK_H_
#define CRYPTOHOME_STORAGE_MOUNT_STACK_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace cryptohome {

// This class is basically a stack that logs an error if it's not empty when
// it's destroyed.
class MountStack {
 public:
  MountStack();
  MountStack(const MountStack&) = delete;
  MountStack& operator=(const MountStack&) = delete;

  virtual ~MountStack();

  virtual void Push(const base::FilePath& src, const base::FilePath& dest);
  virtual bool Pop(base::FilePath* src_out, base::FilePath* dest_out);
  virtual bool ContainsDest(const base::FilePath& dest) const;
  virtual size_t size() const { return mounts_.size(); }

  virtual std::vector<base::FilePath> MountDestinations() const;

 private:
  struct MountInfo {
    MountInfo(const base::FilePath& src, const base::FilePath& dest);

    // Source and destination mount points.
    const base::FilePath src;
    const base::FilePath dest;
  };

  std::vector<MountInfo> mounts_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOUNT_STACK_H_
