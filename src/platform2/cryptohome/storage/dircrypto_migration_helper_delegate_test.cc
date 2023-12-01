// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/dircrypto_migration_helper_delegate.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "cryptohome/migration_type.h"
#include "cryptohome/platform.h"

using base::FilePath;

namespace cryptohome {

namespace {

constexpr char kToDir[] = "/home/.shadow/deadbeef/mount";

}  // namespace

class DircryptoMigrationHelperDelegateTest : public ::testing::Test {
 public:
  DircryptoMigrationHelperDelegateTest() : to_dir_(kToDir) {}
  virtual ~DircryptoMigrationHelperDelegateTest() = default;

  DircryptoMigrationHelperDelegateTest(
      const DircryptoMigrationHelperDelegateTest&) = delete;
  DircryptoMigrationHelperDelegateTest& operator=(
      const DircryptoMigrationHelperDelegateTest&) = delete;

 protected:
  Platform platform_;
  base::FilePath to_dir_;
};

TEST_F(DircryptoMigrationHelperDelegateTest, ShouldMigrateFile_FullMigration) {
  DircryptoMigrationHelperDelegate delegate(&platform_, to_dir_,
                                            MigrationType::FULL);

  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/GCache/v1")));
  EXPECT_FALSE(delegate.ShouldMigrateFile(FilePath("user/GCache/v1/tmp")));
}

TEST_F(DircryptoMigrationHelperDelegateTest,
       ShouldMigrateFile_MinimalMigration) {
  DircryptoMigrationHelperDelegate delegate(&platform_, to_dir_,
                                            MigrationType::MINIMAL);

  // Parent path of allowlisted paths is migrated.
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("root")));

  // Random stuff not on the allowlist is skipped.
  EXPECT_FALSE(delegate.ShouldMigrateFile(FilePath("user/Application Cache")));
  EXPECT_FALSE(delegate.ShouldMigrateFile(FilePath("root/android-data")));
  EXPECT_FALSE(
      delegate.ShouldMigrateFile(FilePath("user/Application Cache/subfile")));
  EXPECT_FALSE(delegate.ShouldMigrateFile(FilePath("user/skipped_file")));
  EXPECT_FALSE(delegate.ShouldMigrateFile(FilePath("root/skipped_file")));

  // Allowlisted directories under root/ are migrated.
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("root/session_manager")));
  EXPECT_TRUE(
      delegate.ShouldMigrateFile(FilePath("root/session_manager/policy")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(
      FilePath("root/session_manager/policy/subfile1")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(
      FilePath("root/session_manager/policy/subfile2")));

  // Allowlisted directories under user/ are migrated.
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/log")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/.pki")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/.pki/nssdb")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/.pki/nssdb/subfile1")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/.pki/nssdb/subfile2")));
  EXPECT_TRUE(delegate.ShouldMigrateFile(FilePath("user/Web Data")));
}

}  // namespace cryptohome
