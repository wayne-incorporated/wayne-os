// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_TEST_FILESYSTEM_H_
#define SMBFS_TEST_FILESYSTEM_H_

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/functional/callback.h>

#include "smbfs/filesystem.h"

namespace smbfs {

// Test/fake filesystem for integration testing.
class TestFilesystem : public Filesystem {
 public:
  TestFilesystem(uid_t uid, gid_t gid);
  TestFilesystem(const TestFilesystem&) = delete;
  TestFilesystem& operator=(const TestFilesystem&) = delete;

  void Lookup(std::unique_ptr<EntryRequest> request,
              fuse_ino_t parent_inode,
              const std::string& name) override;
  void GetAttr(std::unique_ptr<AttrRequest> request, fuse_ino_t inode) override;

 private:
  const uid_t uid_;
  const gid_t gid_;
};

}  // namespace smbfs

#endif  // SMBFS_TEST_FILESYSTEM_H_
