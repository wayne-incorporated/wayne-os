// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/test_filesystem.h"

#include <errno.h>

#include <utility>

namespace smbfs {
namespace {

// Kernel attribute cache timeout, in seconds.
constexpr double kAttrTimeout = 5.0;

}  // namespace

TestFilesystem::TestFilesystem(uid_t uid, gid_t gid) : uid_(uid), gid_(gid) {}

void TestFilesystem::Lookup(std::unique_ptr<EntryRequest> request,
                            fuse_ino_t parent_inode,
                            const std::string& name) {
  request->ReplyError(ENOENT);
}

void TestFilesystem::GetAttr(std::unique_ptr<AttrRequest> request,
                             fuse_ino_t inode) {
  if (inode == FUSE_ROOT_ID) {
    // Root inode.
    struct stat stat = {0};
    stat.st_ino = inode;
    stat.st_mode = S_IFDIR | 0755;
    stat.st_nlink = 1;
    stat.st_uid = uid_;
    stat.st_gid = gid_;
    stat.st_size = 4096;
    request->ReplyAttr(stat, kAttrTimeout);
    return;
  }

  request->ReplyError(ENOENT);
}

}  // namespace smbfs
