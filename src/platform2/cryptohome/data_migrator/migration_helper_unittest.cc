// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/data_migrator/migration_helper.h"

#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/synchronization/waitable_event.h>
#include <base/threading/thread.h>

#include "cryptohome/data_migrator/fake_migration_helper_delegate.h"
#include "cryptohome/migration_type.h"
#include "cryptohome/mock_platform.h"

extern "C" {
#include <linux/fs.h>
}

using base::FilePath;
using testing::_;
using testing::DoDefault;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::NiceMock;
using testing::Return;
using testing::SetErrnoAndReturn;
using testing::Values;

namespace cryptohome::data_migrator {

namespace {

constexpr uint64_t kDefaultChunkSize = 128;

constexpr char kStatusFilesDir[] = "/home/.shadow/deadbeef/status_dir";
constexpr char kFromDir[] = "/home/.shadow/deadbeef/temporary_mount";
constexpr char kToDir[] = "/home/.shadow/deadbeef/mount";

}  // namespace

class MigrationHelperTest : public ::testing::Test {
 public:
  MigrationHelperTest()
      : status_files_dir_(kStatusFilesDir),
        from_dir_(kFromDir),
        to_dir_(kToDir) {}
  virtual ~MigrationHelperTest() {}

  void SetUp() override {
    ASSERT_TRUE(platform_.CreateDirectory(status_files_dir_));
    ASSERT_TRUE(platform_.CreateDirectory(from_dir_));
    ASSERT_TRUE(platform_.CreateDirectory(to_dir_));
  }

  void ProgressCaptor(uint64_t current_bytes, uint64_t total_bytes) {
    migrated_values_.push_back(current_bytes);
    total_values_.push_back(total_bytes);
  }

 protected:
  base::FilePath status_files_dir_;
  base::FilePath from_dir_;
  base::FilePath to_dir_;

  NiceMock<MockPlatform> platform_;
  FakeMigrationHelperDelegate delegate_{&platform_, to_dir_};

  std::vector<uint64_t> migrated_values_;
  std::vector<uint64_t> total_values_;
};

TEST_F(MigrationHelperTest, EmptyTest) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  ASSERT_TRUE(platform_.IsDirectoryEmpty(from_dir_));
  ASSERT_TRUE(platform_.IsDirectoryEmpty(to_dir_));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
}

TEST_F(MigrationHelperTest, CopyAttributesDirectory) {
  // Test that UID/GID, mtime, permission, xattr, ext2 attributes and
  // project quota ID of a directory are migrated.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kDirectory[] = "directory";
  const FilePath kFromDirPath = from_dir_.Append(kDirectory);
  ASSERT_TRUE(platform_.CreateDirectory(kFromDirPath));

  // Set some attributes to this directory.

  constexpr uid_t kUid = 100;
  constexpr gid_t kGid = 200;
  ASSERT_TRUE(platform_.SetOwnership(kFromDirPath, kUid, kGid,
                                     /*follow_links=*/false));

  mode_t kMode = S_ISVTX | S_IRUSR | S_IWUSR | S_IXUSR;
  ASSERT_TRUE(platform_.SetPermissions(kFromDirPath, kMode));

  constexpr char kAttrName[] = "user.attr";
  constexpr char kValue[] = "value";
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(kFromDirPath, kAttrName,
                                                 kValue, sizeof(kValue)));

  // Set ext2 attributes
  int ext2_attrs = FS_SYNC_FL | FS_NODUMP_FL;
  ASSERT_TRUE(platform_.SetExtFileAttributes(kFromDirPath, ext2_attrs));

  // Set project quota ID.
  constexpr int from_project_id = 12345;
  ASSERT_TRUE(platform_.SetQuotaProjectId(kFromDirPath, from_project_id));

  base::stat_wrapper_t from_stat;
  ASSERT_TRUE(platform_.Stat(kFromDirPath, &from_stat));
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  const FilePath kToDirPath = to_dir_.Append(kDirectory);
  EXPECT_TRUE(platform_.DirectoryExists(kToDirPath));

  base::stat_wrapper_t to_stat;
  ASSERT_TRUE(platform_.Stat(kToDirPath, &to_stat));

  // Verify mtime was copied.  atime for directories is not
  // well-preserved because we have to traverse the directories to determine
  // migration size.
  EXPECT_EQ(from_stat.st_mtim.tv_sec, to_stat.st_mtim.tv_sec);
  EXPECT_EQ(from_stat.st_mtim.tv_nsec, to_stat.st_mtim.tv_nsec);

  // Verify UID/GID, permissions and xattrs were copied
  EXPECT_EQ(to_stat.st_uid, kUid);
  EXPECT_EQ(to_stat.st_gid, kGid);
  // GetPermissions call is needed here because some bits have been
  // automatically applied to to_stat.st_mode.
  mode_t to_mode;
  ASSERT_TRUE(platform_.GetPermissions(kToDirPath, &to_mode));
  EXPECT_EQ(to_mode, kMode);
  std::string value;
  ASSERT_TRUE(platform_.GetExtendedFileAttributeAsString(kToDirPath, kAttrName,
                                                         &value));
  EXPECT_STREQ(value.c_str(), kValue);

  // Verify ext2 flags were copied
  int new_ext2_attrs;
  ASSERT_TRUE(platform_.GetExtFileAttributes(kToDirPath, &new_ext2_attrs));
  EXPECT_EQ(ext2_attrs, new_ext2_attrs);

  int to_project_id = 0;
  ASSERT_TRUE(platform_.GetQuotaProjectId(kToDirPath, &to_project_id));
  EXPECT_EQ(from_project_id, to_project_id);
}

TEST_F(MigrationHelperTest, DirectoryPartiallyMigrated) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kDirectory[] = "directory";
  const FilePath kFromDirPath = from_dir_.Append(kDirectory);
  ASSERT_TRUE(platform_.CreateDirectory(kFromDirPath));
  constexpr struct timespec kMtime = {123, 456};
  constexpr struct timespec kAtime = {234, 567};
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(
      to_dir_, delegate_.GetMtimeXattrName(),
      reinterpret_cast<const char*>(&kMtime), sizeof(kMtime)));
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(
      to_dir_, delegate_.GetAtimeXattrName(),
      reinterpret_cast<const char*>(&kAtime), sizeof(kAtime)));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
  base::stat_wrapper_t to_stat;

  // Verify that stored timestamps for in-progress migrations are respected
  ASSERT_TRUE(platform_.Stat(to_dir_, &to_stat));
  EXPECT_EQ(kMtime.tv_sec, to_stat.st_mtim.tv_sec);
  EXPECT_EQ(kMtime.tv_nsec, to_stat.st_mtim.tv_nsec);
  EXPECT_EQ(kAtime.tv_sec, to_stat.st_atim.tv_sec);
  EXPECT_EQ(kAtime.tv_nsec, to_stat.st_atim.tv_nsec);

  // Verify subdirectory was migrated
  const FilePath kToDirPath = to_dir_.Append(kDirectory);
  EXPECT_TRUE(platform_.DirectoryExists(kToDirPath));
}

TEST_F(MigrationHelperTest, CopySymlink) {
  // Test that the symlinks and their targets are migrated correctly.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);
  FilePath target;

  constexpr char kFileName[] = "file";
  constexpr char kAbsLinkTarget[] = "/dev/null";
  const FilePath kTargetInMigrationDirAbsLinkTarget =
      from_dir_.Append(kFileName);
  const FilePath kRelLinkTarget = base::FilePath(kFileName);
  constexpr char kRelLinkName[] = "link1";
  constexpr char kAbsLinkName[] = "link2";
  constexpr char kTargetInMigrationDirAbsLinkName[] = "link3";
  const FilePath kFromRelLinkPath = from_dir_.Append(kRelLinkName);
  const FilePath kFromAbsLinkPath = from_dir_.Append(kAbsLinkName);
  const FilePath kFromTargetInMigrationDirAbsLinkPath =
      from_dir_.Append(kTargetInMigrationDirAbsLinkName);
  ASSERT_TRUE(platform_.CreateSymbolicLink(kFromRelLinkPath, kRelLinkTarget));
  ASSERT_TRUE(platform_.CreateSymbolicLink(kFromAbsLinkPath,
                                           base::FilePath(kAbsLinkTarget)));
  ASSERT_TRUE(platform_.CreateSymbolicLink(kFromTargetInMigrationDirAbsLinkPath,
                                           kTargetInMigrationDirAbsLinkTarget));
  base::stat_wrapper_t from_stat;
  ASSERT_TRUE(platform_.Stat(kFromRelLinkPath, &from_stat));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  const FilePath kToFilePath = to_dir_.Append(kFileName);
  const FilePath kToRelLinkPath = to_dir_.Append(kRelLinkName);
  const FilePath kToAbsLinkPath = to_dir_.Append(kAbsLinkName);
  const FilePath kToTargetInMigrationDirAbsLinkPath =
      to_dir_.Append(kTargetInMigrationDirAbsLinkName);
  const FilePath kExpectedTargetInMigrationDirAbsLinkTarget =
      to_dir_.Append(kFileName);

  // Verify that all links have been copied correctly
  EXPECT_TRUE(platform_.ReadLink(kToRelLinkPath, &target));
  EXPECT_EQ(kRelLinkTarget.value(), target.value());
  EXPECT_TRUE(platform_.ReadLink(kToAbsLinkPath, &target));
  EXPECT_EQ(kAbsLinkTarget, target.value());
  EXPECT_TRUE(platform_.ReadLink(kToTargetInMigrationDirAbsLinkPath, &target));
  EXPECT_EQ(kExpectedTargetInMigrationDirAbsLinkTarget.value(), target.value());
}

TEST_F(MigrationHelperTest, OneEmptyFile) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "empty_file";

  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append(kFileName)));
  ASSERT_TRUE(platform_.IsDirectoryEmpty(to_dir_));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // The file is moved.
  EXPECT_FALSE(platform_.FileExists(from_dir_.Append(kFileName)));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append(kFileName)));
}

TEST_F(MigrationHelperTest, OneEmptyFileInNestedDirectory) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kDir1[] = "directory1";
  constexpr char kDir2[] = "directory2";
  constexpr char kFileName[] = "empty_file";

  // Create directory1/directory2/empty_file in from_dir_.
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append(kDir1).Append(kDir2)));
  ASSERT_TRUE(platform_.TouchFileDurable(
      from_dir_.Append(kDir1).Append(kDir2).Append(kFileName)));
  ASSERT_TRUE(platform_.IsDirectoryEmpty(to_dir_));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // The file is moved.
  EXPECT_FALSE(platform_.FileExists(
      from_dir_.Append(kDir1).Append(kDir2).Append(kFileName)));
  EXPECT_TRUE(platform_.IsDirectoryEmpty(from_dir_.Append(kDir1)));
  EXPECT_TRUE(platform_.FileExists(
      to_dir_.Append(kDir1).Append(kDir2).Append(kFileName)));
}

TEST_F(MigrationHelperTest, UnreadableFile) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kDir1[] = "directory1";
  constexpr char kDir2[] = "directory2";
  constexpr char kFileName[] = "empty_file";

  // Create directory1/directory2/empty_file in from_dir_.  File will be
  // unreadable to test failure case.
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append(kDir1).Append(kDir2)));
  ASSERT_TRUE(platform_.TouchFileDurable(
      from_dir_.Append(kDir1).Append(kDir2).Append(kFileName)));
  ASSERT_TRUE(platform_.IsDirectoryEmpty(to_dir_));
  ASSERT_TRUE(platform_.SetPermissions(
      from_dir_.Append(kDir1).Append(kDir2).Append(kFileName), S_IWUSR));

  EXPECT_FALSE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // The file is not moved.
  EXPECT_TRUE(platform_.FileExists(
      from_dir_.Append(kDir1).Append(kDir2).Append(kFileName)));
}

TEST_F(MigrationHelperTest, CopyAttributesFile) {
  // Test that UID/GID, mtime/atime, permission, xattr, ext2 attributes and
  // project quota ID of a file are migrated.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "file";
  const FilePath kFromFilePath = from_dir_.Append(kFileName);
  const FilePath kToFilePath = to_dir_.Append(kFileName);

  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append(kFileName)));

  // Set some attributes to this file.

  constexpr uid_t kUid = 1;
  constexpr gid_t kGid = 2;
  ASSERT_TRUE(platform_.SetOwnership(kFromFilePath, kUid, kGid,
                                     /*follow_links=*/false));

  mode_t kMode = S_ISVTX | S_IRUSR | S_IWUSR | S_IXUSR;
  ASSERT_TRUE(platform_.SetPermissions(kFromFilePath, kMode));

  constexpr char kAttrName[] = "user.attr";
  constexpr char kValue[] = "value";
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(kFromFilePath, kAttrName,
                                                 kValue, sizeof(kValue)));
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(
      kFromFilePath, kSourceURLXattrName, kValue, sizeof(kValue)));
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(
      kFromFilePath, kReferrerURLXattrName, kValue, sizeof(kValue)));

  // Set ext2 attributes
  int ext2_attrs = FS_SYNC_FL | FS_NODUMP_FL | EXT4_EOFBLOCKS_FL;
  ASSERT_TRUE(platform_.SetExtFileAttributes(kFromFilePath, ext2_attrs));

  // Set project quota ID.
  constexpr int from_project_id = 12345;
  ASSERT_TRUE(platform_.SetQuotaProjectId(kFromFilePath, from_project_id));

  base::stat_wrapper_t from_stat;
  ASSERT_TRUE(platform_.Stat(kFromFilePath, &from_stat));
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  EXPECT_TRUE(platform_.FileExists(kToFilePath));

  base::stat_wrapper_t to_stat;
  ASSERT_TRUE(platform_.Stat(kToFilePath, &to_stat));
  EXPECT_EQ(from_stat.st_atim.tv_sec, to_stat.st_atim.tv_sec);
  EXPECT_EQ(from_stat.st_atim.tv_nsec, to_stat.st_atim.tv_nsec);
  EXPECT_EQ(from_stat.st_mtim.tv_sec, to_stat.st_mtim.tv_sec);
  EXPECT_EQ(from_stat.st_mtim.tv_nsec, to_stat.st_mtim.tv_nsec);
  EXPECT_EQ(to_stat.st_uid, kUid);
  EXPECT_EQ(to_stat.st_gid, kGid);
  // GetPermissions call is needed here because some bits have been
  // automatically applied to to_stat.st_mode.
  mode_t to_mode;
  ASSERT_TRUE(platform_.GetPermissions(kToFilePath, &to_mode));
  EXPECT_EQ(to_mode, kMode);

  std::string value;
  ASSERT_TRUE(platform_.GetExtendedFileAttributeAsString(kToFilePath, kAttrName,
                                                         &value));
  EXPECT_STREQ(value.c_str(), kValue);

  // The temporary xattrs for storing mtime/atime should be removed.
  ASSERT_FALSE(platform_.GetExtendedFileAttribute(
      kToFilePath, delegate_.GetMtimeXattrName(), nullptr, 0));
  ASSERT_EQ(ENODATA, errno);
  ASSERT_FALSE(platform_.GetExtendedFileAttribute(
      kToFilePath, delegate_.GetAtimeXattrName(), nullptr, 0));
  ASSERT_EQ(ENODATA, errno);

  // Quarantine xattrs storing the origin and referrer of downloaded files
  // should also be removed.
  ASSERT_FALSE(platform_.GetExtendedFileAttribute(
      kToFilePath, kSourceURLXattrName, nullptr, 0));
  ASSERT_EQ(ENODATA, errno);
  ASSERT_FALSE(platform_.GetExtendedFileAttribute(
      kToFilePath, kReferrerURLXattrName, nullptr, 0));
  ASSERT_EQ(ENODATA, errno);

  // Verify ext2 flags were copied, but older flags are excluded.
  int new_ext2_attrs;
  ASSERT_TRUE(platform_.GetExtFileAttributes(kToFilePath, &new_ext2_attrs));
  EXPECT_EQ(ext2_attrs & ~EXT4_EOFBLOCKS_FL, new_ext2_attrs);

  int to_project_id = 0;
  ASSERT_TRUE(platform_.GetQuotaProjectId(kToFilePath, &to_project_id));
  EXPECT_EQ(from_project_id, to_project_id);
}

TEST_F(MigrationHelperTest, CopyAttributesSymlink) {
  // Test that UID/GID, mtime/atime and xattrs of a symlink are migrated.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  const FilePath kFromLink = from_dir_.Append("link");
  const FilePath kToLink = to_dir_.Append("link");
  ASSERT_TRUE(platform_.CreateSymbolicLink(kFromLink, FilePath("/dev/null")));

  // Set some attributes to this symlink.

  constexpr uid_t kUid = 10;
  constexpr gid_t kGid = 20;
  ASSERT_TRUE(platform_.SetOwnership(kFromLink, kUid, kGid,
                                     /*follow_links=*/false));

  constexpr char kAttrName[] = "user.attr";
  constexpr char kValue[] = "value";
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(kFromLink, kAttrName, kValue,
                                                 sizeof(kValue)));

  base::stat_wrapper_t from_stat;
  ASSERT_TRUE(platform_.Stat(kFromLink, &from_stat));
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  base::stat_wrapper_t to_stat;
  EXPECT_TRUE(platform_.Stat(kToLink, &to_stat));
  EXPECT_EQ(from_stat.st_atim.tv_sec, to_stat.st_atim.tv_sec);
  EXPECT_EQ(from_stat.st_atim.tv_nsec, to_stat.st_atim.tv_nsec);
  EXPECT_EQ(from_stat.st_mtim.tv_sec, to_stat.st_mtim.tv_sec);
  EXPECT_EQ(from_stat.st_mtim.tv_nsec, to_stat.st_mtim.tv_nsec);
  EXPECT_EQ(to_stat.st_uid, kUid);
  EXPECT_EQ(to_stat.st_gid, kGid);

  std::string value;
  ASSERT_TRUE(
      platform_.GetExtendedFileAttributeAsString(kToLink, kAttrName, &value));
  EXPECT_STREQ(value.c_str(), kValue);
}

TEST_F(MigrationHelperTest, ConvertFileMetadata) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);
  constexpr uid_t kFromErrorUid = 0;
  constexpr uid_t kFromFileUid = 10001;
  constexpr uid_t kFromDirUid = 10002;
  constexpr uid_t kToFileUid = 20001;
  constexpr uid_t kToDirUid = 20002;
  constexpr gid_t kGid = 1000;

  // Map |kFromErrorUid| to null so that files with this UID won't be migrated.
  delegate_.AddUidMapping(kFromErrorUid, /*uid_to=*/std::nullopt);
  // Map |kFromFileUid| to |kToFileUid|, and |kFromDirUid| to |kToDirUid|.
  delegate_.AddUidMapping(kFromFileUid, kToFileUid);
  delegate_.AddUidMapping(kFromDirUid, kToDirUid);

  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("file1")));
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("file2")));
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append("dir1")));
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("dir1/file")));
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append("dir2")));
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("dir2/file")));

  // file1 and dir1 have UID |kFromErrorUid|.
  ASSERT_TRUE(platform_.SetOwnership(from_dir_.Append("file1"), kFromErrorUid,
                                     kGid, /*follow_links=*/false));
  ASSERT_TRUE(platform_.SetOwnership(from_dir_.Append("dir1"), kFromErrorUid,
                                     kGid, /*follow_links=*/false));

  // file2, dir2 and dir2/file all have UID that can be converted.
  ASSERT_TRUE(platform_.SetOwnership(from_dir_.Append("file2"), kFromFileUid,
                                     kGid, /*follow_links=*/false));
  ASSERT_TRUE(platform_.SetOwnership(from_dir_.Append("dir2"), kFromDirUid,
                                     kGid, /*follow_links=*/false));
  ASSERT_TRUE(platform_.SetOwnership(from_dir_.Append("dir2/file"),
                                     kFromFileUid, kGid,
                                     /*follow_links=*/false));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // file1 and dir1 are not migrated because their UID cannot be converted.
  EXPECT_FALSE(platform_.FileExists(to_dir_.Append("file1")));
  EXPECT_FALSE(platform_.DirectoryExists(to_dir_.Append("dir1")));

  // file2 and dir2 are migrated because their UID can be converted.
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append("file2")));
  EXPECT_TRUE(platform_.DirectoryExists(to_dir_.Append("dir2")));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append("dir2/file")));

  // Check that the UID of file2 and dir2 are correctly converted.
  uid_t to_file2_uid = 0, to_dir2_uid = 0;
  gid_t to_gid = 0;
  EXPECT_TRUE(platform_.GetOwnership(to_dir_.Append("file2"), &to_file2_uid,
                                     &to_gid, /*follow_links=*/false));
  EXPECT_EQ(to_file2_uid, kToFileUid);
  EXPECT_TRUE(platform_.GetOwnership(to_dir_.Append("dir2"), &to_dir2_uid,
                                     &to_gid, /*follow_links=*/false));
  EXPECT_EQ(to_dir2_uid, kToDirUid);
}

TEST_F(MigrationHelperTest, ConvertXattrName) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "file";
  const FilePath kFromFilePath = from_dir_.Append(kFileName);
  const FilePath kToFilePath = to_dir_.Append(kFileName);
  ASSERT_TRUE(platform_.TouchFileDurable(kFromFilePath));

  constexpr char kValue1[] = "value1";
  constexpr char kValue2[] = "value2";

  // Convert user.from1 to user.to1.
  delegate_.AddXattrMapping("user.from1", "user.to1");

  ASSERT_TRUE(platform_.SetExtendedFileAttribute(kFromFilePath, "user.from1",
                                                 kValue1, sizeof(kValue1)));
  ASSERT_TRUE(platform_.SetExtendedFileAttribute(kFromFilePath, "user.from2",
                                                 kValue2, sizeof(kValue2)));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // user.from1 is converted to user.to1.
  ASSERT_FALSE(platform_.GetExtendedFileAttributeAsString(
      kToFilePath, "user.from1", nullptr));
  ASSERT_EQ(ENODATA, errno);

  std::string value1;
  ASSERT_TRUE(platform_.GetExtendedFileAttributeAsString(kToFilePath,
                                                         "user.to1", &value1));
  EXPECT_STREQ(kValue1, value1.c_str());

  // user.from2 is not converted.
  std::string value2;
  ASSERT_TRUE(platform_.GetExtendedFileAttributeAsString(
      kToFilePath, "user.from2", &value2));
  EXPECT_STREQ(kValue2, value2.c_str());
}

TEST_F(MigrationHelperTest, SkipCopyingTimeOnMtimeENOSPC) {
  // Test the case where mtime and atime of a file were not migrated because
  // setting time xattr for mtime resulted in ENOSPC failure.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  const FilePath kFromFile = from_dir_.Append("file");
  const FilePath kToFile = to_dir_.Append("file");
  ASSERT_TRUE(platform_.TouchFileDurable(kFromFile));

  // Storing mtime in xattr fails with ENOSPC.
  EXPECT_CALL(platform_, SetExtendedFileAttribute(_, _, _, _))
      .WillRepeatedly(DoDefault());
  EXPECT_CALL(platform_, SetExtendedFileAttribute(
                             kToFile, delegate_.GetMtimeXattrName(), _, _))
      .WillOnce(SetErrnoAndReturn(ENOSPC, false));

  base::stat_wrapper_t from_stat;
  ASSERT_TRUE(platform_.Stat(kFromFile, &from_stat));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // File is migrated and removed from the source.
  base::stat_wrapper_t to_stat;
  EXPECT_TRUE(platform_.Stat(kToFile, &to_stat));
  EXPECT_FALSE(platform_.FileExists(kFromFile));

  // The temporary xattr for storing atime should not exist.
  ASSERT_FALSE(platform_.GetExtendedFileAttribute(
      kToFile, delegate_.GetAtimeXattrName(), nullptr, 0));
  ASSERT_EQ(ENODATA, errno);
}

TEST_F(MigrationHelperTest, SkipCopyingTimeOnAtimeENOSPC) {
  // Test the case where mtime and atime of a file were not migrated because
  // setting time xattr for atime resulted in ENOSPC failure.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  const FilePath kFromFile = from_dir_.Append("file");
  const FilePath kToFile = to_dir_.Append("file");
  ASSERT_TRUE(platform_.TouchFileDurable(kFromFile));

  // Storing atime in xattr fails with ENOSPC.
  EXPECT_CALL(platform_, SetExtendedFileAttribute(_, _, _, _))
      .WillRepeatedly(DoDefault());
  EXPECT_CALL(platform_, SetExtendedFileAttribute(
                             kToFile, delegate_.GetAtimeXattrName(), _, _))
      .WillOnce(SetErrnoAndReturn(ENOSPC, false));

  base::stat_wrapper_t from_stat;
  ASSERT_TRUE(platform_.Stat(kFromFile, &from_stat));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // File is migrated and removed from the source.
  base::stat_wrapper_t to_stat;
  EXPECT_TRUE(platform_.Stat(kToFile, &to_stat));
  EXPECT_FALSE(platform_.FileExists(kFromFile));

  // The temporary xattr for storing mtime should not exist.
  ASSERT_FALSE(platform_.GetExtendedFileAttribute(
      kToFile, delegate_.GetMtimeXattrName(), nullptr, 0));
  ASSERT_EQ(ENODATA, errno);
}

TEST_F(MigrationHelperTest, MigrateInProgress) {
  // Test the case where the migration was interrupted part way through, but in
  // a clean way such that the two directory trees are consistent (files are
  // only present in one or the other)
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFile1[] = "kFile1";
  constexpr char kFile2[] = "kFile2";
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append(kFile1)));
  ASSERT_TRUE(platform_.TouchFileDurable(to_dir_.Append(kFile2)));
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // Both files have been moved to to_dir_
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append(kFile1)));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append(kFile2)));
  EXPECT_FALSE(platform_.FileExists(from_dir_.Append(kFile1)));
  EXPECT_FALSE(platform_.FileExists(from_dir_.Append(kFile2)));
}

TEST_F(MigrationHelperTest, MigrateInProgressDuplicateFile) {
  // Test the case where the migration was interrupted part way through,
  // resulting in files that were successfully written to destination but not
  // yet removed from the source.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFile1[] = "kFile1";
  constexpr char kFile2[] = "kFile2";
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append(kFile1)));
  ASSERT_TRUE(platform_.TouchFileDurable(to_dir_.Append(kFile1)));
  ASSERT_TRUE(platform_.TouchFileDurable(to_dir_.Append(kFile2)));
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // Both files have been moved to to_dir_
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append(kFile1)));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append(kFile2)));
  EXPECT_FALSE(platform_.FileExists(from_dir_.Append(kFile1)));
  EXPECT_FALSE(platform_.FileExists(from_dir_.Append(kFile2)));
}

TEST_F(MigrationHelperTest, MigrateInProgressPartialFile) {
  // Test the case where the migration was interrupted part way through, with a
  // file having been partially copied to the destination but not fully.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "file";
  const FilePath kFromFilePath = from_dir_.Append(kFileName);
  const FilePath kToFilePath = to_dir_.Append(kFileName);

  const size_t kFinalFileSize = kDefaultChunkSize * 2;
  const size_t kFromFileSize = kDefaultChunkSize;
  const size_t kToFileSize = kDefaultChunkSize;
  char full_contents[kFinalFileSize];
  base::RandBytes(full_contents, kFinalFileSize);

  ASSERT_TRUE(
      platform_.WriteArrayToFile(kFromFilePath, full_contents, kFromFileSize));
  base::File kToFile;
  platform_.InitializeFile(&kToFile, kToFilePath,
                           base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(kToFile.IsValid());
  kToFile.SetLength(kFinalFileSize);
  const size_t kToFileOffset = kFinalFileSize - kToFileSize;
  ASSERT_EQ(
      kToFileSize,
      kToFile.Write(kToFileOffset, full_contents + kToFileOffset, kToFileSize));
  ASSERT_EQ(kFinalFileSize, kToFile.GetLength());
  kToFile.Close();

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // File has been moved to to_dir_
  std::string to_contents;
  ASSERT_TRUE(platform_.ReadFileToString(kToFilePath, &to_contents));
  EXPECT_EQ(std::string(full_contents, kFinalFileSize), to_contents);
  EXPECT_FALSE(platform_.FileExists(kFromFilePath));
}

TEST_F(MigrationHelperTest, MigrateInProgressPartialFileDuplicateData) {
  // Test the case where the migration was interrupted part way through, with a
  // file having been partially copied to the destination but the source file
  // not yet having been truncated to reflect that.
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "file";
  const FilePath kFromFilePath = from_dir_.Append(kFileName);
  const FilePath kToFilePath = to_dir_.Append(kFileName);

  const size_t kFinalFileSize = kDefaultChunkSize * 2;
  const size_t kFromFileSize = kFinalFileSize;
  const size_t kToFileSize = kDefaultChunkSize;
  char full_contents[kFinalFileSize];
  base::RandBytes(full_contents, kFinalFileSize);

  ASSERT_TRUE(
      platform_.WriteArrayToFile(kFromFilePath, full_contents, kFromFileSize));
  base::File kToFile;
  platform_.InitializeFile(&kToFile, kToFilePath,
                           base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(kToFile.IsValid());
  kToFile.SetLength(kFinalFileSize);
  const size_t kToFileOffset = kFinalFileSize - kToFileSize;
  ASSERT_EQ(
      kDefaultChunkSize,
      kToFile.Write(kToFileOffset, full_contents + kToFileOffset, kToFileSize));
  ASSERT_EQ(kFinalFileSize, kToFile.GetLength());
  kToFile.Close();

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // File has been moved to to_dir_
  std::string to_contents;
  ASSERT_TRUE(platform_.ReadFileToString(kToFilePath, &to_contents));
  EXPECT_EQ(std::string(full_contents, kFinalFileSize), to_contents);
  EXPECT_FALSE(platform_.FileExists(kFromFilePath));
}

TEST_F(MigrationHelperTest, ProgressCallback) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "file";
  constexpr char kLinkName[] = "link";
  constexpr char kDirName[] = "dir";
  const FilePath kFromSubdir = from_dir_.Append(kDirName);
  const FilePath kFromFile = kFromSubdir.Append(kFileName);
  const FilePath kFromLink = kFromSubdir.Append(kLinkName);
  const FilePath kToSubdir = to_dir_.Append(kDirName);
  const FilePath kToFile = kToSubdir.Append(kFileName);

  const size_t kFileSize = kDefaultChunkSize;
  char from_contents[kFileSize];
  base::RandBytes(from_contents, kFileSize);
  ASSERT_TRUE(platform_.CreateDirectory(kFromSubdir));
  ASSERT_TRUE(platform_.CreateSymbolicLink(kFromLink, kFromFile.BaseName()));
  ASSERT_TRUE(platform_.WriteArrayToFile(kFromFile, from_contents, kFileSize));
  int64_t expected_size = kFileSize;
  expected_size += kFromFile.BaseName().value().length();
  int64_t dir_size;
  ASSERT_TRUE(platform_.GetFileSize(kFromSubdir, &dir_size));
  expected_size += dir_size;

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  ASSERT_EQ(migrated_values_.size(), total_values_.size());
  int callbacks = migrated_values_.size();
  EXPECT_GT(callbacks, 2);
  EXPECT_EQ(callbacks, total_values_.size());

  // Verify that migrated value starts at 0 and increases to total
  EXPECT_EQ(0, migrated_values_[1]);
  for (int i = 2; i < callbacks - 1; i++) {
    SCOPED_TRACE(i);
    EXPECT_GE(migrated_values_[i], migrated_values_[i - 1]);
  }
  EXPECT_EQ(expected_size, migrated_values_[callbacks - 1]);

  // Verify that total always matches the expected size except for the first
  // report where it is 0.
  EXPECT_EQ(0, total_values_[0]);
  EXPECT_EQ(callbacks, total_values_.size());
  for (int i = 1; i < callbacks; i++) {
    SCOPED_TRACE(i);
    EXPECT_EQ(expected_size, total_values_[i]);
  }
}

TEST_F(MigrationHelperTest, NotEnoughFreeSpace) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  delegate_.SetFreeDiskSpaceForMigrator(0);
  EXPECT_FALSE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
}

TEST_F(MigrationHelperTest, ForceSmallerChunkSize) {
  constexpr int kMaxChunkSize = 128 << 20;  // 128MB
  constexpr int kNumJobThreads = 2;
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kMaxChunkSize);
  helper.set_num_job_threads_for_testing(kNumJobThreads);

  constexpr int kFreeSpace = 13 << 20;
  // Chunk size should be limited to a multiple of 4MB (kErasureBlockSize)
  // smaller than (kFreeSpace - kFreeSpaceBuffer) / kNumJobThreads (4MB)
  constexpr int kExpectedChunkSize = 4 << 20;
  constexpr int kFileSize = 7 << 20;
  const FilePath kFromFilePath = from_dir_.Append("file");
  base::File from_file;
  platform_.InitializeFile(&from_file, kFromFilePath,
                           base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(from_file.IsValid());

  from_file.SetLength(kFileSize);
  from_file.Close();

  delegate_.SetFreeDiskSpaceForMigrator(kFreeSpace);
  EXPECT_CALL(platform_, SendFile(_, _, kExpectedChunkSize,
                                  kFileSize - kExpectedChunkSize))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, SendFile(_, _, 0, kExpectedChunkSize))
      .WillOnce(Return(true));
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
}

TEST_F(MigrationHelperTest, SkipInvalidSQLiteFiles) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);
  const char kCorruptedFilePath[] =
      "root/android-data/data/user/0/com.google.android.gms/"
      "databases/playlog.db-shm";
  const FilePath kFromSQLiteShm = from_dir_.Append(kCorruptedFilePath);
  const FilePath kToSQLiteShm = to_dir_.Append(kCorruptedFilePath);
  ASSERT_TRUE(platform_.CreateDirectory(kFromSQLiteShm.DirName()));
  ASSERT_TRUE(platform_.TouchFileDurable(kFromSQLiteShm));
  EXPECT_CALL(platform_, InitializeFile(_, _, _)).WillRepeatedly(DoDefault());
  EXPECT_CALL(platform_, InitializeFile(_, kFromSQLiteShm, _))
      .WillOnce(
          Invoke([](base::File* file, const FilePath& path, uint32_t mode) {
            *file = base::File(base::File::FILE_ERROR_IO);
          }));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
  EXPECT_TRUE(platform_.DirectoryExists(kToSQLiteShm.DirName()));
  EXPECT_FALSE(platform_.FileExists(kToSQLiteShm));
  EXPECT_FALSE(platform_.FileExists(kFromSQLiteShm));
}

TEST_F(MigrationHelperTest, AllJobThreadsFailing) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr int kNumJobThreads = 2;
  helper.set_num_job_threads_for_testing(kNumJobThreads);
  helper.set_max_job_list_size_for_testing(1);

  // Create more files than the job threads.
  for (int i = 0; i < kNumJobThreads * 2; ++i) {
    ASSERT_TRUE(platform_.TouchFileDurable(
        from_dir_.AppendASCII(base::NumberToString(i))));
  }
  // All job threads will stop processing jobs because of errors. Also, set
  // errno to avoid confusing base::File::OSErrorToFileError(). crbug.com/731809
  EXPECT_CALL(platform_, DeleteFile(_))
      .WillRepeatedly(SetErrnoAndReturn(EIO, false));
  // Migrate() still returns the result without deadlocking. crbug.com/731575
  EXPECT_FALSE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
}

TEST_F(MigrationHelperTest, CheckSkippedFiles) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  // Structure:
  //   dir/             -> not skipped
  //     skip_dir/      -> skipped
  //       file         -> skipped
  //     skip_file      -> skipped
  //     nonskip_dir/   -> not skipped
  //       file         -> not skipped
  //     nonskip_file   -> not skipped
  //   file             -> not skipped
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append("dir")));
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append("dir/skip_dir")));
  ASSERT_TRUE(platform_.CreateDirectory(from_dir_.Append("dir/nonskip_dir")));
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("file")));
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("dir/skip_file")));
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append("dir/nonskip_file")));
  ASSERT_TRUE(
      platform_.TouchFileDurable(from_dir_.Append("dir/skip_dir/file")));
  ASSERT_TRUE(
      platform_.TouchFileDurable(from_dir_.Append("dir/nonskip_dir/file")));

  delegate_.AddDenylistedPath(FilePath("dir/skip_dir"));
  delegate_.AddDenylistedPath(FilePath("dir/skip_file"));

  // Test the migration.
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // Check that dir/skip_dir/* and dir/skip_file were not migrated.
  EXPECT_FALSE(platform_.DirectoryExists(to_dir_.Append("dir/skip_dir")));
  EXPECT_FALSE(platform_.FileExists(to_dir_.Append("dir/skip_dir/file")));
  EXPECT_FALSE(platform_.FileExists(to_dir_.Append("dir/skip_file")));

  // Check that everything else were migrated.
  EXPECT_TRUE(platform_.DirectoryExists(to_dir_.Append("dir")));
  EXPECT_TRUE(platform_.DirectoryExists(to_dir_.Append("dir/nonskip_dir")));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append("file")));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append("dir/nonskip_file")));
  EXPECT_TRUE(platform_.FileExists(to_dir_.Append("dir/nonskip_dir/file")));

  // Check that the source is empty.
  EXPECT_TRUE(platform_.IsDirectoryEmpty(from_dir_));
}

TEST_F(MigrationHelperTest, CancelMigrationBeforeStart) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  // Cancel migration before starting, and migration just fails.
  helper.Cancel();
  EXPECT_FALSE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
}

TEST_F(MigrationHelperTest, CancelMigrationOnAnotherThread) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  // One empty file to migrate.
  constexpr char kFileName[] = "empty_file";
  ASSERT_TRUE(platform_.TouchFileDurable(from_dir_.Append(kFileName)));
  // Wait in SyncFile so that cancellation happens before migration finishes.
  base::WaitableEvent syncfile_is_called_event(
      base::WaitableEvent::ResetPolicy::AUTOMATIC,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  base::WaitableEvent cancel_is_called_event(
      base::WaitableEvent::ResetPolicy::AUTOMATIC,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  EXPECT_CALL(platform_, SyncFile(to_dir_.Append(kFileName)))
      .WillOnce(InvokeWithoutArgs(
          [&syncfile_is_called_event, &cancel_is_called_event]() {
            syncfile_is_called_event.Signal();
            cancel_is_called_event.Wait();
            return true;
          }));

  // Cancel on another thread after waiting for SyncFile to get called.
  base::Thread thread("Canceller thread");
  ASSERT_TRUE(thread.Start());
  thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&base::WaitableEvent::Wait,
                                base::Unretained(&syncfile_is_called_event)));
  thread.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&MigrationHelper::Cancel, base::Unretained(&helper)));
  thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&base::WaitableEvent::Signal,
                                base::Unretained(&cancel_is_called_event)));
  // Migration gets cancelled.
  EXPECT_FALSE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));
}

class DataMigrationTest : public MigrationHelperTest,
                          public ::testing::WithParamInterface<size_t> {};

TEST_P(DataMigrationTest, CopyFileData) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);

  constexpr char kFileName[] = "file";
  const FilePath kFromFile = from_dir_.Append(kFileName);
  const FilePath kToFile = to_dir_.Append(kFileName);

  const size_t kFileSize = GetParam();
  char from_contents[kFileSize];
  base::RandBytes(from_contents, kFileSize);
  ASSERT_TRUE(platform_.WriteArrayToFile(kFromFile, from_contents, kFileSize));

  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  std::string to_contents;
  ASSERT_TRUE(platform_.ReadFileToString(kToFile, &to_contents));
  EXPECT_EQ(0, strncmp(from_contents, to_contents.data(), kFileSize));
  EXPECT_FALSE(platform_.FileExists(kFromFile));
}

INSTANTIATE_TEST_SUITE_P(WithRandomData,
                         DataMigrationTest,
                         Values(kDefaultChunkSize / 2,
                                kDefaultChunkSize,
                                kDefaultChunkSize * 2,
                                kDefaultChunkSize * 2 + kDefaultChunkSize / 2,
                                kDefaultChunkSize * 10,
                                kDefaultChunkSize * 100,
                                123456,
                                1,
                                2));

// MigrationHelperJobListTest verifies that the job list size limit doesn't
// cause dead lock, however small (or big) the limit is.
class MigrationHelperJobListTest
    : public MigrationHelperTest,
      public ::testing::WithParamInterface<size_t> {};

TEST_P(MigrationHelperJobListTest, ProcessJobs) {
  MigrationHelper helper(&platform_, &delegate_, from_dir_, to_dir_,
                         status_files_dir_, kDefaultChunkSize);
  helper.set_max_job_list_size_for_testing(GetParam());

  // Prepare many files and directories.
  constexpr int kNumDirectories = 100;
  constexpr int kNumFilesPerDirectory = 10;
  for (int i = 0; i < kNumDirectories; ++i) {
    SCOPED_TRACE(i);
    FilePath dir = from_dir_.AppendASCII(base::NumberToString(i));
    ASSERT_TRUE(platform_.CreateDirectory(dir));
    for (int j = 0; j < kNumFilesPerDirectory; ++j) {
      SCOPED_TRACE(j);
      const std::string data =
          base::NumberToString(i * kNumFilesPerDirectory + j);
      ASSERT_TRUE(platform_.WriteStringToFile(
          dir.AppendASCII(base::NumberToString(j)), data));
    }
  }

  // Migrate.
  EXPECT_TRUE(helper.Migrate(base::BindRepeating(
      &MigrationHelperTest::ProgressCaptor, base::Unretained(this))));

  // The files and directories are moved.
  for (int i = 0; i < kNumDirectories; ++i) {
    SCOPED_TRACE(i);
    FilePath dir = to_dir_.AppendASCII(base::NumberToString(i));
    EXPECT_TRUE(platform_.DirectoryExists(dir));
    for (int j = 0; j < kNumFilesPerDirectory; ++j) {
      SCOPED_TRACE(j);
      std::string data;
      EXPECT_TRUE(platform_.ReadFileToString(
          dir.AppendASCII(base::NumberToString(j)), &data));
      EXPECT_EQ(base::NumberToString(i * kNumFilesPerDirectory + j), data);
    }
  }
  EXPECT_TRUE(platform_.IsDirectoryEmpty(from_dir_));
}

INSTANTIATE_TEST_SUITE_P(JobListSize,
                         MigrationHelperJobListTest,
                         Values(1, 10, 100, 1000));

}  // namespace cryptohome::data_migrator
