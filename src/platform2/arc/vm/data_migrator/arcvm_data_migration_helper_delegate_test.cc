// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/arcvm_data_migration_helper_delegate.h"

#include <errno.h>

#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

using cryptohome::data_migrator::FailureLocationType;

namespace arc::data_migrator {

namespace {

constexpr char kDummySourcePath[] =
    "/home/root/0123456789abcdef0123456789abcdef01234567/android-data/data";

constexpr uid_t kAndroidRootUid = 655360;
constexpr gid_t kAndroidRootGid = 655360;

struct MapPathToPathTypeTestCase {
  std::string rel_path;
  FailedPathType type_source;
  FailedPathType type_dest;
  FailedPathType type_source_or_dest;
};

}  // namespace

class ArcVmDataMigrationHelperDelegateTest : public ::testing::Test {
 public:
  ArcVmDataMigrationHelperDelegateTest()
      : source_(base::FilePath(kDummySourcePath)),
        dest_(base::FilePath(kDestinationMountPoint)) {}
  virtual ~ArcVmDataMigrationHelperDelegateTest() = default;

  ArcVmDataMigrationHelperDelegateTest(
      const ArcVmDataMigrationHelperDelegateTest&) = delete;
  ArcVmDataMigrationHelperDelegateTest& operator=(
      const ArcVmDataMigrationHelperDelegateTest&) = delete;

 protected:
  const base::FilePath source_;
  const base::FilePath dest_;
};

TEST_F(ArcVmDataMigrationHelperDelegateTest, ConvertUid) {
  // We can pass nullptr for metrics since we don't test metrics reporting.
  ArcVmDataMigrationHelperDelegate delegate(source_, nullptr /* metrics */);

  // Valid host-to-guest UID mappings (pairs of (host UID, guest UID)).
  std::vector<std::pair<uid_t, uid_t>> mapping_test_cases = {{
      // [655360, 660360) is mapped to [0, 5000).
      {655360, 0},     // AID_ROOT
      {656360, 1000},  // AID_SYSTEM
      {657360, 2000},  // AID_SHELL (adb)
      {660359, 4999},

      // [600, 650) is mapped to [5000, 5050).
      {600, 5000},
      {602, 5002},  // arc-bridge
      {649, 5049},

      // [660410, 2655360) is mapped to [5050, 2000000).
      {660410, 5050},
  }};

  // Host UIDs that will not be mapped to a valid guest UID.
  std::vector<uid_t> out_of_range_host_uids = {0, 650, 1000, 660360};

  for (const auto& [host_uid, guest_uid] : mapping_test_cases) {
    base::stat_wrapper_t stat;
    stat.st_uid = host_uid;
    stat.st_gid = kAndroidRootGid;  // Avoid warning spams for invalid GID.
    EXPECT_TRUE(delegate.ConvertFileMetadata(&stat));
    EXPECT_EQ(stat.st_uid, guest_uid);
  }

  for (const auto& host_uid : out_of_range_host_uids) {
    base::stat_wrapper_t stat;
    stat.st_uid = host_uid;
    stat.st_gid = kAndroidRootGid;  // Avoid warning spams for invalid GID.
    EXPECT_FALSE(delegate.ConvertFileMetadata(&stat));
  }
}

TEST_F(ArcVmDataMigrationHelperDelegateTest, ConvertGid) {
  // We can pass nullptr for metrics since we don't test metrics reporting.
  ArcVmDataMigrationHelperDelegate delegate(source_, nullptr /* metrics */);

  // Valid host-to-guest GID mappings (pairs of (host GID, guest GID)).
  std::vector<std::pair<gid_t, gid_t>> mapping_test_cases = {{
      // [655360, 656425) is mapped to [0, 1065).
      {655360, 0},     // AID_ROOT
      {656360, 1000},  // AID_SYSTEM
      {656424, 1064},

      // 20119 (android-reserved-disk) is mapped to 1065 (AID_RESERVED_DISK).
      {20119, 1065},

      // [656426, 660360) is mapped to [1066, 5000).
      {656426, 1066},
      {657360, 2000},  // AID_SHELL (adb)
      {660359, 4999},

      // [600, 650) is mapped to [5000, 5050).
      {600, 5000},
      {602, 5002},  // arc-bridge
      {649, 5049},

      // [660410, 2655360) is mapped to [5050, 2000000).
      {660410, 5050},
  }};

  // Host GIDs that will not be mapped to a valid guest GID.
  std::vector<gid_t> out_of_range_host_gids = {0, 650, 1000, 656425, 660360};

  for (const auto& [host_gid, guest_gid] : mapping_test_cases) {
    base::stat_wrapper_t stat;
    stat.st_gid = host_gid;
    stat.st_uid = kAndroidRootUid;  // Avoid warning spams for invalid UID.
    EXPECT_TRUE(delegate.ConvertFileMetadata(&stat));
    EXPECT_EQ(stat.st_gid, guest_gid);
  }

  for (const auto& host_gid : out_of_range_host_gids) {
    base::stat_wrapper_t stat;
    stat.st_gid = host_gid;
    stat.st_uid = kAndroidRootUid;  // Avoid warning spams for invalid UID.
    EXPECT_FALSE(delegate.ConvertFileMetadata(&stat));
  }
}

TEST_F(ArcVmDataMigrationHelperDelegateTest, ConvertXattrName) {
  // We can pass nullptr for metrics since we don't test metrics reporting.
  ArcVmDataMigrationHelperDelegate delegate(source_, nullptr /* metrics */);

  // user.virtiofs.security.* is converted to security.*.
  EXPECT_EQ(delegate.ConvertXattrName("user.virtiofs.security.sehash"),
            "security.sehash");
  // Other xattrs are kept as-is.
  EXPECT_EQ(delegate.ConvertXattrName("security.selinux"), "security.selinux");
  EXPECT_EQ(delegate.ConvertXattrName("user.attr"), "user.attr");
  EXPECT_EQ(delegate.ConvertXattrName("system.attr"), "system.attr");
  EXPECT_EQ(delegate.ConvertXattrName("trusted.attr"), "trusted.attr");
}

TEST_F(ArcVmDataMigrationHelperDelegateTest, MapPathToPathType) {
  ArcVmDataMigrationHelperDelegate delegate(source_, nullptr);

  std::vector<MapPathToPathTypeTestCase> test_cases{{
      {"media/0", FailedPathType::kOtherSource, FailedPathType::kOtherDest,
       FailedPathType::kOther},
      {"media/0/Pictures", FailedPathType::kMediaSource,
       FailedPathType::kMediaDest, FailedPathType::kMedia},
      {"media/0/Pictures/capybara.jpg", FailedPathType::kMediaSource,
       FailedPathType::kMediaDest, FailedPathType::kMedia},
      {"media/0/Android/data/", FailedPathType::kMediaSource,
       FailedPathType::kMediaDest, FailedPathType::kMedia},
      {"media/0/Android/data/com.android.vending/files",
       FailedPathType::kMediaAndroidDataSource,
       FailedPathType::kMediaAndroidDataDest,
       FailedPathType::kMediaAndroidData},
      {"media/0/Android/obb/com.android.vending/files",
       FailedPathType::kMediaAndroidObbSource,
       FailedPathType::kMediaAndroidObbDest, FailedPathType::kMediaAndroidObb},
      {"data/com.android.vending/cache", FailedPathType::kDataSource,
       FailedPathType::kDataDest, FailedPathType::kData},
      {"app/~~JBwEbfOhkonCF0Y2Fb5Bdw==/"
       "com.android.vending-DZtQ0em8Lw17vh1IWICRYQ==/lib",
       FailedPathType::kAppSource, FailedPathType::kAppDest,
       FailedPathType::kApp},
      {"user/0/com.android.vending/cache", FailedPathType::kUserSource,
       FailedPathType::kUserDest, FailedPathType::kUser},
      {"user_de/0/com.android.vending/cache", FailedPathType::kUserDeSource,
       FailedPathType::kUserDeDest, FailedPathType::kUserDe},
      {"system/packages.xml", FailedPathType::kOtherSource,
       FailedPathType::kOtherDest, FailedPathType::kOther},
  }};

  for (const auto& test_case : test_cases) {
    EXPECT_EQ(delegate.MapPathToPathType(base::FilePath(test_case.rel_path),
                                         FailureLocationType::kSource),
              test_case.type_source);
    EXPECT_EQ(delegate.MapPathToPathType(base::FilePath(test_case.rel_path),
                                         FailureLocationType::kDest),
              test_case.type_dest);
    EXPECT_EQ(delegate.MapPathToPathType(base::FilePath(test_case.rel_path),
                                         FailureLocationType::kSourceOrDest),
              test_case.type_source_or_dest);

    // Absolute paths are supported as well. Whether the absolute path is in the
    // migration source or in the destination does not change the result of
    // MapPathToPathType.
    EXPECT_EQ(delegate.MapPathToPathType(source_.Append(test_case.rel_path),
                                         FailureLocationType::kSourceOrDest),
              test_case.type_source_or_dest);
    EXPECT_EQ(delegate.MapPathToPathType(dest_.Append(test_case.rel_path),
                                         FailureLocationType::kSource),
              test_case.type_source);
  }

  // Absolute paths that is not under the migration source or the destination
  // are categorized separately.
  EXPECT_EQ(
      delegate.MapPathToPathType(base::FilePath("/data/media/0/Android/data"),
                                 FailureLocationType::kSource),
      FailedPathType::kUnknownAbsolutePath);
}

TEST_F(ArcVmDataMigrationHelperDelegateTest,
       GetAccessDeniedAtOpenFileFailureType) {
  ArcVmDataMigrationHelperDelegate delegate(source_, nullptr /* metrics */);

  const base::FilePath references_parent(
      source_.Append("data/com.example.app/files/../cache"));
  const base::FilePath references_parent_false_positive(
      source_.Append("data/com.example.app/files/.../cache"));
  const base::FilePath valid_path(source_.Append("data/com.example.app/cache"));

  EXPECT_EQ(
      delegate.GetAccessDeniedAtOpenFileFailureType(references_parent, EACCES),
      AccessDeniedAtOpenFileFailureType::kReferencesParent);
  // Check a false positive case introduced by crbug/181617 if it has not been
  // fixed yet.
  if (references_parent_false_positive.ReferencesParent()) {
    EXPECT_EQ(
        delegate.GetAccessDeniedAtOpenFileFailureType(
            references_parent_false_positive, EACCES),
        AccessDeniedAtOpenFileFailureType::kReferencesParentFalsePositive);
  }
  EXPECT_EQ(delegate.GetAccessDeniedAtOpenFileFailureType(valid_path, EACCES),
            AccessDeniedAtOpenFileFailureType::kPermissionDenied);
  EXPECT_EQ(delegate.GetAccessDeniedAtOpenFileFailureType(valid_path, EISDIR),
            AccessDeniedAtOpenFileFailureType::kIsADirectory);
  EXPECT_EQ(delegate.GetAccessDeniedAtOpenFileFailureType(valid_path, EROFS),
            AccessDeniedAtOpenFileFailureType::kReadOnlyFileSystem);
  EXPECT_EQ(delegate.GetAccessDeniedAtOpenFileFailureType(valid_path, EPERM),
            AccessDeniedAtOpenFileFailureType::kOperationNotPermitted);
  EXPECT_EQ(delegate.GetAccessDeniedAtOpenFileFailureType(valid_path, ENOENT),
            AccessDeniedAtOpenFileFailureType::kOther);
}

}  // namespace arc::data_migrator
