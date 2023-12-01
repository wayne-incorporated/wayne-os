// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fusebox/make_stat.h"

#include <memory>

#include <base/files/file.h>
#include <gtest/gtest.h>

namespace fusebox {

TEST(MakeStatTest, IsAllowedStatMode) {
  // File and directory mode types are allowed.
  ASSERT_TRUE(IsAllowedStatMode(mode_t(S_IFREG)));
  ASSERT_TRUE(IsAllowedStatMode(mode_t(S_IFDIR)));

  // Other mode types are not allowed.
  mode_t other = mode_t(~(S_IFREG | S_IFDIR));
  ASSERT_FALSE(IsAllowedStatMode(other));
}

TEST(MakeStatTest, StatModeToStringDirectory) {
  const mode_t dir = S_IFDIR;  // directory
  ASSERT_EQ("drwxrwxrwx", StatModeToString(dir | 0777));

  mode_t user = dir | (S_IRUSR | S_IWUSR | S_IXUSR);
  ASSERT_EQ("drwx------", StatModeToString(user));
  mode_t group = user | (S_IRGRP | S_IWGRP | S_IXGRP);
  ASSERT_EQ("drwxrwx---", StatModeToString(group));
  mode_t other = group | (S_IROTH | S_IWOTH | S_IXOTH);
  ASSERT_EQ("drwxrwxrwx", StatModeToString(other));

  mode_t rx = other & ~(S_IWUSR | S_IWGRP | S_IWOTH);
  ASSERT_EQ("dr-xr-xr-x", StatModeToString(rx));
  mode_t x = rx & ~(S_IRUSR | S_IRGRP | S_IROTH);
  ASSERT_EQ("d--x--x--x", StatModeToString(x));
}

TEST(MakeStatTest, StatModeToStringFile) {
  const mode_t reg = S_IFREG;  // regular file
  ASSERT_EQ("-rwxrwxrwx", StatModeToString(reg | 0777));

  mode_t user = reg | (S_IRUSR | S_IWUSR | S_IXUSR);
  ASSERT_EQ("-rwx------", StatModeToString(user));
  mode_t group = user | (S_IRGRP | S_IWGRP | S_IXGRP);
  ASSERT_EQ("-rwxrwx---", StatModeToString(group));
  mode_t other = group | (S_IROTH | S_IWOTH | S_IXOTH);
  ASSERT_EQ("-rwxrwxrwx", StatModeToString(other));

  mode_t rw = other & ~(S_IXUSR | S_IXGRP | S_IXOTH);
  ASSERT_EQ("-rw-rw-rw-", StatModeToString(rw));
  mode_t r = rw & ~(S_IWUSR | S_IWGRP | S_IWOTH);
  ASSERT_EQ("-r--r--r--", StatModeToString(r));
}

TEST(MakeStatTest, MakeStatModeBits) {
  const bool read_only = true;

  // Test default directory permissions.
  mode_t mode = MakeStatModeBits(S_IFDIR | 0777);
  EXPECT_EQ("drwxrwx---", StatModeToString(mode));
  mode_t permissions = mode & 0777;
  EXPECT_EQ(0770, permissions);

  // Test default directory permissions: read only.
  mode = MakeStatModeBits(S_IFDIR | 0777, read_only);
  EXPECT_EQ("dr-xr-x---", StatModeToString(mode));
  permissions = mode & 0777;
  EXPECT_EQ(0550, permissions);

  // Test default file permissions.
  mode = MakeStatModeBits(S_IFREG | 0777);
  EXPECT_EQ("-rw-rw----", StatModeToString(mode));
  permissions = mode & 0777;
  EXPECT_EQ(0660, permissions);

  // Test default file permissions: read only.
  mode = MakeStatModeBits(S_IFREG | 0777, read_only);
  EXPECT_EQ("-r--r-----", StatModeToString(mode));
  permissions = mode & 0777;
  EXPECT_EQ(0440, permissions);

  // Directory "other" permission bits should be cleared.
  EXPECT_FALSE(MakeStatModeBits(S_IFDIR | S_IRWXO) & S_IRWXO);

  // File "other" permission bits should be cleared.
  EXPECT_FALSE(MakeStatModeBits(S_IFREG | S_IRWXO) & S_IRWXO);

  // Directory should have group execute bit set.
  EXPECT_TRUE(MakeStatModeBits(S_IFDIR | 0777) & S_IXGRP);

  // File should not have group execute bit set.
  EXPECT_FALSE(MakeStatModeBits(S_IFREG | 0777) & S_IXGRP);

  // Directory should have user execute bit set.
  EXPECT_TRUE(MakeStatModeBits(S_IFDIR | 0777) & S_IXUSR);

  // File should not have user execute bit set.
  EXPECT_FALSE(MakeStatModeBits(S_IFREG | 0777) & S_IXUSR);

  // Directory group RW bits should equal user RW bits.
  mode = S_IFDIR | S_IRUSR | S_IWUSR;
  mode_t expect = mode | S_IRGRP | S_IWGRP | S_IXUSR | S_IXGRP;
  EXPECT_EQ(expect, MakeStatModeBits(mode));

  // Directory group RW bits should equal RW user bits: read only case.
  mode = S_IFDIR | S_IRUSR | S_IWUSR;
  expect = S_IFDIR | S_IRUSR | S_IRGRP | S_IXUSR | S_IXGRP;
  EXPECT_EQ(expect, MakeStatModeBits(mode, read_only));

  // File group bits should equal user bits.
  mode = S_IFREG | S_IRUSR | S_IWUSR;
  expect = mode | S_IRGRP | S_IWGRP;
  EXPECT_EQ(expect, MakeStatModeBits(mode));

  // File group bits should equal user bits: read only case.
  mode = S_IFREG | S_IRUSR | S_IWUSR | S_IXUSR;
  expect = S_IFREG | S_IRUSR | S_IRGRP;
  EXPECT_EQ(expect, MakeStatModeBits(mode, read_only));
}

TEST(MakeStatTest, MakeTimeStat) {
  const time_t kTimeNow = std::time(nullptr);

  // Test directory mode.
  struct stat dir = {0};
  dir.st_mode = mode_t(S_IFDIR | 0755);
  dir.st_atime = kTimeNow;
  dir.st_mtime = kTimeNow;
  dir.st_ctime = kTimeNow;

  struct stat dir_stat = MakeTimeStat(dir.st_mode, kTimeNow);
  EXPECT_EQ("drwxr-xr-x", StatModeToString(dir_stat.st_mode));
  EXPECT_EQ(0, std::memcmp(&dir_stat, &dir, sizeof(dir)));

  // Test regular file mode.
  struct stat reg = {0};
  reg.st_mode = mode_t(S_IFREG | 0644);
  reg.st_atime = kTimeNow;
  reg.st_mtime = kTimeNow;
  reg.st_ctime = kTimeNow;

  struct stat reg_stat = MakeTimeStat(reg.st_mode, kTimeNow);
  EXPECT_EQ("-rw-r--r--", StatModeToString(reg_stat.st_mode));
  EXPECT_EQ(0, std::memcmp(&reg_stat, &reg, sizeof(reg)));

  // Other modes are not allowed.
  struct stat other = {0};
  other.st_mode = mode_t(~(S_IFDIR | S_IFREG));
  EXPECT_DEATH(MakeTimeStat(other.st_mode, kTimeNow), "");
}

TEST(MakeStatTest, MakeStat) {
  const bool read_only = true;
  const ino_t ino = 1;

  // MakeStat sets these stat fields only.
  struct stat expected = {0};
  expected.st_ino = ino;
  expected.st_mode = 0;
  expected.st_nlink = 1;
  expected.st_uid = kChronosUID;
  expected.st_gid = kChronosAccessGID;

  for (const mode_t type : {S_IFDIR, S_IFREG}) {
    struct stat stat = {0};

    // MakeStat uses MakeStatModeBits to synthesize stat.st_mode perms.
    stat.st_mode = type | 0777;
    expected.st_mode = MakeStatModeBits(stat.st_mode);
    EXPECT_NE(expected.st_mode, stat.st_mode);

    // MakeStat preserves other stat fields.
    static int i = 0;
    stat.st_dev = ++i;
    stat.st_size = ++i;
    stat.st_rdev = ++i;
    stat.st_atime = ++i;
    stat.st_mtime = ++i;
    stat.st_ctime = ++i;

    // Call MakeStat to create a stat with synthesized perms.
    struct stat out = MakeStat(ino, stat);

    // Test stat field preservation.
    EXPECT_EQ(stat.st_dev, out.st_dev);
    EXPECT_EQ(stat.st_size, out.st_size);
    EXPECT_EQ(stat.st_rdev, out.st_rdev);
    EXPECT_EQ(stat.st_atime, out.st_atime);
    EXPECT_EQ(stat.st_mtime, out.st_mtime);
    EXPECT_EQ(stat.st_ctime, out.st_ctime);

    // Test stat field alteration and .st_mode perms synthesis.
    EXPECT_EQ(expected.st_ino, out.st_ino);
    EXPECT_EQ(expected.st_mode, out.st_mode);
    EXPECT_EQ(expected.st_nlink, out.st_nlink);
    EXPECT_EQ(expected.st_uid, out.st_uid);
    EXPECT_EQ(expected.st_gid, out.st_gid);

    // Calling MakeStat with read only should clear write perms.
    stat.st_mode = type | 0777;
    mode_t write = (S_IWUSR | S_IWGRP | S_IWOTH);
    EXPECT_EQ(write, stat.st_mode & write);
    out = MakeStat(ino, stat, read_only);
    EXPECT_EQ(0, out.st_mode & write);
  }
}

}  // namespace fusebox
