// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/inode_map.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

namespace smbfs {
namespace {

constexpr ino_t kRootInode = 7;
constexpr char kFilePath1[] = "/foo";
constexpr char kFilePath2[] = "/foo/bar";

TEST(InodeMapTest, TestRootInode) {
  InodeMap map(kRootInode);

  EXPECT_TRUE(map.PathExists(base::FilePath("/")));
  EXPECT_EQ(base::FilePath("/"), map.GetPath(kRootInode));
  EXPECT_EQ(kRootInode, map.IncInodeRef(base::FilePath("/")));
}

TEST(InodeMapTest, TestInsertLookup) {
  InodeMap map(kRootInode);

  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath1)));
  ino_t inode1 = map.IncInodeRef(base::FilePath(kFilePath1));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_NE(inode1, kRootInode);
  EXPECT_EQ(inode1, map.IncInodeRef(base::FilePath(kFilePath1)));
  EXPECT_EQ(base::FilePath(kFilePath1), map.GetPath(inode1));

  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath2)));
  ino_t inode2 = map.IncInodeRef(base::FilePath(kFilePath2));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath2)));
  EXPECT_NE(inode2, kRootInode);
  EXPECT_NE(inode2, inode1);
  EXPECT_EQ(inode2, map.IncInodeRef(base::FilePath(kFilePath2)));
  EXPECT_EQ(base::FilePath(kFilePath2), map.GetPath(inode2));
}

TEST(InodeMapTest, TestInsertLookupNonExistent) {
  InodeMap map(kRootInode);

  EXPECT_EQ(base::FilePath(), map.GetPath(kRootInode + 1));
}

TEST(InodeMapTest, TestInsertEmpty) {
  InodeMap map(kRootInode);
  EXPECT_DEATH(map.IncInodeRef(base::FilePath()), ".*path\\.empty.*");
}

TEST(InodeMapTest, TestInsertNonAbsolute) {
  InodeMap map(kRootInode);
  EXPECT_DEATH(map.IncInodeRef(base::FilePath("foo")), ".*path\\.IsAbsolute.*");
}

TEST(InodeMapTest, TestInsertRelative) {
  InodeMap map(kRootInode);
  EXPECT_DEATH(map.IncInodeRef(base::FilePath("/foo/../bar")),
               ".*path\\.ReferencesParent.*");
}

TEST(InodeMapTest, TestForget) {
  InodeMap map(kRootInode);

  // Create inode with refcount of 3.
  ino_t inode1 = map.IncInodeRef(base::FilePath(kFilePath1));
  map.IncInodeRef(base::FilePath(kFilePath1));
  map.IncInodeRef(base::FilePath(kFilePath1));
  EXPECT_EQ(base::FilePath(kFilePath1), map.GetPath(inode1));

  // Create inode with refcount of 2.
  ino_t inode2 = map.IncInodeRef(base::FilePath(kFilePath2));
  map.IncInodeRef(base::FilePath(kFilePath2));
  EXPECT_EQ(base::FilePath(kFilePath2), map.GetPath(inode2));

  bool removed = map.Forget(inode1, 2);
  EXPECT_EQ(base::FilePath(kFilePath1), map.GetPath(inode1));
  EXPECT_FALSE(removed);
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath1)));

  removed = map.Forget(inode1, 1);
  EXPECT_EQ(base::FilePath(), map.GetPath(inode1));
  EXPECT_TRUE(removed);
  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath1)));

  // Previous Forget() calls shouldn't affect |inode2|.
  EXPECT_EQ(base::FilePath(kFilePath2), map.GetPath(inode2));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath2)));

  removed = map.Forget(inode2, 2);
  EXPECT_EQ(base::FilePath(), map.GetPath(inode2));
  EXPECT_TRUE(removed);
  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath2)));
}

TEST(InodeMapTest, TestForgetRoot) {
  InodeMap map(kRootInode);

  // Forgetting the root inode should do nothing.
  bool removed = map.Forget(kRootInode, 1);
  EXPECT_EQ(base::FilePath("/"), map.GetPath(kRootInode));
  EXPECT_FALSE(removed);
}

TEST(InodeMapTest, TestForgetTooMany) {
  InodeMap map(kRootInode);

  ino_t inode1 = map.IncInodeRef(base::FilePath(kFilePath1));
  EXPECT_DEATH(map.Forget(inode1, 2), "Check failed.*");
}

TEST(InodeMapTest, TestForgetWeak) {
  InodeMap map(kRootInode);

  ino_t inode1 = map.GetWeakInode(base::FilePath(kFilePath1));
  EXPECT_DEATH(map.Forget(inode1, 1), "Check failed.*");
}

TEST(InodeMapTest, TestUpdatePath) {
  InodeMap map(kRootInode);

  ino_t inode1 = map.IncInodeRef(base::FilePath(kFilePath1));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath1)));
  map.UpdatePath(inode1, base::FilePath(kFilePath2));
  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath2)));
  EXPECT_EQ(inode1, map.IncInodeRef(base::FilePath(kFilePath2)));
  EXPECT_EQ(base::FilePath(kFilePath2), map.GetPath(inode1));

  // Re-adding the original path should create a new inode.
  ino_t inode2 = map.IncInodeRef(base::FilePath(kFilePath1));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_NE(inode2, kRootInode);
  EXPECT_NE(inode2, inode1);
  EXPECT_EQ(inode2, map.IncInodeRef(base::FilePath(kFilePath1)));
  EXPECT_EQ(base::FilePath(kFilePath1), map.GetPath(inode2));
}

TEST(InodeMapTest, TestGetWeakInode) {
  InodeMap map(kRootInode);

  ino_t inode1 = map.GetWeakInode(base::FilePath(kFilePath1));
  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_TRUE(map.GetPath(inode1).empty());
  ino_t inode2 = map.IncInodeRef(base::FilePath(kFilePath2));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath2)));
  EXPECT_GT(inode2, inode1);

  // Return the same inode in future calls to GetWeakInode(). The inode remains
  // weak.
  EXPECT_EQ(inode1, map.GetWeakInode(base::FilePath(kFilePath1)));
  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_TRUE(map.GetPath(inode1).empty());

  // Solidify the inode.
  EXPECT_EQ(inode1, map.IncInodeRef(base::FilePath(kFilePath1)));
  EXPECT_TRUE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_EQ(map.GetPath(inode1), base::FilePath(kFilePath1));

  // Forgetting and creating a new weak inode should return a different inode.
  EXPECT_TRUE(map.Forget(inode1, 1));
  ino_t inode3 = map.GetWeakInode(base::FilePath(kFilePath1));
  EXPECT_FALSE(map.PathExists(base::FilePath(kFilePath1)));
  EXPECT_TRUE(map.GetPath(inode3).empty());
  EXPECT_GT(inode3, inode1);
}

}  // namespace
}  // namespace smbfs
