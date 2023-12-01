// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/mock_log.h>
#include <brillo/file_utils.h>
#include <crypto/sha2.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dlcservice/test_utils.h"
#include "dlcservice/utils.h"

namespace dlcservice {

using ::testing::_;
using ::testing::HasSubstr;

namespace {
constexpr char kDlcRootPath[] = "/tmp/dlc/";
constexpr char kDlcId[] = "id";
constexpr char kDlcPackage[] = "package";
}  // namespace

class FixtureUtilsTest : public testing::Test {
 protected:
  void SetUp() override { CHECK(scoped_temp_dir_.CreateUniqueTempDir()); }

  void CheckPerms(const base::FilePath& path, const int& expected_perms) {
    int actual_perms = -1;
    EXPECT_TRUE(base::GetPosixFilePermissions(path, &actual_perms));
    EXPECT_EQ(actual_perms, expected_perms);
  }

  bool IsFileSparse(const base::FilePath& path) {
    base::ScopedFD fd(brillo::OpenSafely(path, O_RDONLY, 0));
    EXPECT_TRUE(fd.is_valid());

    struct stat stat {};
    EXPECT_EQ(0, fstat(fd.get(), &stat));
    return stat.st_blksize * stat.st_blocks < stat.st_size;
  }

  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(FixtureUtilsTest, WriteToImage) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
  std::string actual_data;

  // Write "hello".
  EXPECT_TRUE(WriteToImage(path, "hello"));
  EXPECT_TRUE(base::ReadFileToString(path, &actual_data));
  EXPECT_EQ(actual_data, "hello");

  // Write "helloworld".
  EXPECT_TRUE(WriteToImage(path, "helloworld"));
  EXPECT_TRUE(base::ReadFileToString(path, &actual_data));
  EXPECT_EQ(actual_data, "helloworld");

  // Write "world", but file had "helloworld" -> "worldoworld".
  EXPECT_TRUE(WriteToImage(path, "world"));
  EXPECT_TRUE(base::ReadFileToString(path, &actual_data));
  EXPECT_EQ(actual_data, "worldworld");
}

TEST_F(FixtureUtilsTest, WriteToFile) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
  std::string actual_data;

  // Write "hello".
  EXPECT_TRUE(WriteToFile(path, "hello"));
  EXPECT_TRUE(base::ReadFileToString(path, &actual_data));
  EXPECT_EQ(actual_data, "hello");

  // Write "helloworld".
  EXPECT_TRUE(WriteToFile(path, "helloworld"));
  EXPECT_TRUE(base::ReadFileToString(path, &actual_data));
  EXPECT_EQ(actual_data, "helloworld");

  // Write "world".
  EXPECT_TRUE(WriteToFile(path, "world"));
  EXPECT_TRUE(base::ReadFileToString(path, &actual_data));
  EXPECT_EQ(actual_data, "world");
}

TEST_F(FixtureUtilsTest, WriteToFilePermissionsCheck) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
  EXPECT_FALSE(base::PathExists(path));
  EXPECT_TRUE(WriteToFile(path, ""));
  CheckPerms(path, kDlcFilePerms);
}

TEST_F(FixtureUtilsTest, CreateDir) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "dir");
  EXPECT_FALSE(base::DirectoryExists(path));
  EXPECT_TRUE(CreateDir(path));
  EXPECT_TRUE(base::DirectoryExists(path));
  CheckPerms(path, kDlcDirectoryPerms);
}

TEST_F(FixtureUtilsTest, CreateSparseFile) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
  base::File file(path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  EXPECT_TRUE(file.IsValid());
  EXPECT_TRUE(file.SetLength(4096 * 1024));
  EXPECT_TRUE(IsFileSparse(path));
}

TEST_F(FixtureUtilsTest, CreateFile) {
  for (auto&& size : {0, 1, 4096, 4096 * 1024}) {
    auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
    EXPECT_FALSE(base::PathExists(path));
    EXPECT_TRUE(CreateFile(path, size));
    EXPECT_TRUE(base::PathExists(path));
    CheckPerms(path, kDlcFilePerms);
    EXPECT_FALSE(IsFileSparse(path));
    EXPECT_EQ(GetFileSize(path), size);
    EXPECT_TRUE(base::DeletePathRecursively(path));
  }
}

TEST_F(FixtureUtilsTest, CreateFileEvenIfItExists) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
  EXPECT_FALSE(base::PathExists(path));
  EXPECT_TRUE(CreateFile(path, 4096));
  EXPECT_TRUE(base::PathExists(path));
  CheckPerms(path, kDlcFilePerms);
  EXPECT_EQ(GetFileSize(path), 4096);

  // Create again with different size.
  EXPECT_TRUE(CreateFile(path, 8192));
  EXPECT_TRUE(base::PathExists(path));
  EXPECT_EQ(GetFileSize(path), 8192);
}

TEST_F(FixtureUtilsTest, ResizeFile) {
  auto path = JoinPaths(scoped_temp_dir_.GetPath(), "file");
  EXPECT_TRUE(CreateFile(path, 0));
  EXPECT_EQ(GetFileSize(path), 0);
  EXPECT_FALSE(IsFileSparse(path));

  EXPECT_TRUE(ResizeFile(path, 1));

  EXPECT_EQ(GetFileSize(path), 1);
  EXPECT_FALSE(IsFileSparse(path));
}

TEST_F(FixtureUtilsTest, CopyAndHashFile) {
  auto src_path = JoinPaths(scoped_temp_dir_.GetPath(), "src_file");
  auto dst_path = JoinPaths(scoped_temp_dir_.GetPath(), "dst_file");

  EXPECT_FALSE(base::PathExists(src_path));
  EXPECT_FALSE(base::PathExists(dst_path));
  EXPECT_TRUE(CreateFile(src_path, 10));

  std::string file_content;
  EXPECT_TRUE(base::ReadFileToString(src_path, &file_content));
  std::vector<uint8_t> expected_sha256(crypto::kSHA256Length);
  crypto::SHA256HashString(file_content, expected_sha256.data(),
                           expected_sha256.size());

  std::vector<uint8_t> actual_sha256;
  EXPECT_TRUE(CopyAndHashFile(src_path, dst_path, GetFileSize(src_path),
                              &actual_sha256));
  EXPECT_THAT(actual_sha256, testing::ElementsAreArray(expected_sha256));

  EXPECT_TRUE(base::PathExists(dst_path));
  CheckPerms(dst_path, kDlcFilePerms);
}

TEST_F(FixtureUtilsTest, CopyAndHashFileFailOnSize) {
  auto src_path = JoinPaths(scoped_temp_dir_.GetPath(), "src_file");
  auto dst_path = JoinPaths(scoped_temp_dir_.GetPath(), "dst_file");
  EXPECT_TRUE(CreateFile(src_path, 10));

  std::vector<uint8_t> actual_sha256;
  EXPECT_FALSE(CopyAndHashFile(src_path, dst_path, 11, &actual_sha256));
}

TEST_F(FixtureUtilsTest, HashFile) {
  auto src_path = JoinPaths(scoped_temp_dir_.GetPath(), "src_file");
  EXPECT_TRUE(CreateFile(src_path, 10));

  std::string file_content;
  EXPECT_TRUE(base::ReadFileToString(src_path, &file_content));

  std::vector<uint8_t> expected_sha256(crypto::kSHA256Length);
  crypto::SHA256HashString(file_content, expected_sha256.data(),
                           expected_sha256.size());

  std::vector<uint8_t> actual_sha256;
  EXPECT_TRUE(HashFile(src_path, GetFileSize(src_path), &actual_sha256));
  EXPECT_THAT(actual_sha256, testing::ElementsAreArray(expected_sha256));
}

TEST_F(FixtureUtilsTest, HashFileFailOnSize) {
  auto src_path = JoinPaths(scoped_temp_dir_.GetPath(), "src_file");
  EXPECT_TRUE(CreateFile(src_path, 10));

  std::vector<uint8_t> actual_sha256;
  EXPECT_FALSE(HashFile(src_path, 11, &actual_sha256));
}

TEST_F(FixtureUtilsTest, HashEmptyFile) {
  auto src_path = JoinPaths(scoped_temp_dir_.GetPath(), "src_file");
  EXPECT_TRUE(CreateFile(src_path, 0));

  std::string file_content;
  EXPECT_TRUE(base::ReadFileToString(src_path, &file_content));

  std::vector<uint8_t> expected_sha256(crypto::kSHA256Length);
  crypto::SHA256HashString(file_content, expected_sha256.data(),
                           expected_sha256.size());

  std::vector<uint8_t> actual_sha256;
  EXPECT_TRUE(HashFile(src_path, 0, &actual_sha256));
  EXPECT_THAT(actual_sha256, testing::ElementsAreArray(expected_sha256));
}

TEST_F(FixtureUtilsTest, HashMissingFile) {
  auto src_path = JoinPaths(scoped_temp_dir_.GetPath(), "src_file");

  std::vector<uint8_t> actual_sha256;
  EXPECT_FALSE(HashFile(src_path, 0, &actual_sha256));
}

TEST(UtilsTest, JoinPathsTest) {
  EXPECT_EQ(JoinPaths(base::FilePath(kDlcRootPath), kDlcId).value(),
            "/tmp/dlc/id");
  EXPECT_EQ(
      JoinPaths(base::FilePath(kDlcRootPath), kDlcId, kDlcPackage).value(),
      "/tmp/dlc/id/package");
}

TEST(UtilsTest, GetDlcModuleImagePathA) {
  EXPECT_EQ(GetDlcImagePath(base::FilePath(kDlcRootPath), kDlcId, kDlcPackage,
                            BootSlot::Slot::A)
                .value(),
            "/tmp/dlc/id/package/dlc_a/dlc.img");
}

TEST(UtilsTest, GetDlcModuleImagePathB) {
  EXPECT_EQ(GetDlcImagePath(base::FilePath(kDlcRootPath), kDlcId, kDlcPackage,
                            BootSlot::Slot::B)
                .value(),
            "/tmp/dlc/id/package/dlc_b/dlc.img");
}

TEST(UtilsTest, SplitAndJoinPartitionNameTest) {
  std::string disk;
  int part_num;

  EXPECT_TRUE(SplitPartitionName("/dev/sda3", &disk, &part_num));
  EXPECT_EQ("/dev/sda", disk);
  EXPECT_EQ(3, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/sdp1234", &disk, &part_num));
  EXPECT_EQ("/dev/sdp", disk);
  EXPECT_EQ(1234, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/mmcblk0p3", &disk, &part_num));
  EXPECT_EQ("/dev/mmcblk0", disk);
  EXPECT_EQ(3, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/ubiblock3_2", &disk, &part_num));
  EXPECT_EQ("/dev/ubiblock", disk);
  EXPECT_EQ(3, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/loop10", &disk, &part_num));
  EXPECT_EQ("/dev/loop", disk);
  EXPECT_EQ(10, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/loop28p11", &disk, &part_num));
  EXPECT_EQ("/dev/loop28", disk);
  EXPECT_EQ(11, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/loop10_0", &disk, &part_num));
  EXPECT_EQ("/dev/loop", disk);
  EXPECT_EQ(10, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/loop28p11_0", &disk, &part_num));
  EXPECT_EQ("/dev/loop28", disk);
  EXPECT_EQ(11, part_num);

  EXPECT_TRUE(SplitPartitionName("/dev/123", &disk, &part_num));
  EXPECT_EQ("/dev/", disk);
  EXPECT_EQ(123, part_num);

  EXPECT_FALSE(SplitPartitionName("/dev/mmcblk0p", &disk, &part_num));
  EXPECT_FALSE(SplitPartitionName("/dev/sda", &disk, &part_num));
  EXPECT_FALSE(SplitPartitionName("/dev/foo/bar", &disk, &part_num));
  EXPECT_FALSE(SplitPartitionName("/", &disk, &part_num));
  EXPECT_FALSE(SplitPartitionName("", &disk, &part_num));
  EXPECT_FALSE(SplitPartitionName("/dev/_100", &disk, &part_num));
}

TEST(UtilsTest, JoinPartitionNameTest) {
  EXPECT_EQ("/dev/sda3", JoinPartitionName("/dev/sda", 3));
  EXPECT_EQ("/dev/sdp1234", JoinPartitionName("/dev/sdp", 1234));
  EXPECT_EQ("/dev/sdp0p1234", JoinPartitionName("/dev/sdp0", 1234));
  EXPECT_EQ("/dev/mmcblk0p3", JoinPartitionName("/dev/mmcblk0", 3));
  EXPECT_EQ("", JoinPartitionName("foobar", 123));
  EXPECT_EQ("", JoinPartitionName("/dev/sda", 0));
}

TEST(UtilsTest, AlertLogTagCreationTest) {
  auto category = "test_category";
  auto default_component = "CoreServicesAlert";
  EXPECT_EQ(base::StringPrintf("[%s<%s>] ", default_component, category),
            AlertLogTag(category));
}

TEST(UtilsTest, AlertLogTagLogTest) {
  base::test::MockLog mock_log;
  mock_log.StartCapturingLogs();

  auto category = "test_category";
  auto test_msg = "Test Error Message: ";
  auto test_id = 10;
  auto expected_log = base::StringPrintf(
      "%s%s%d", AlertLogTag(category).c_str(), test_msg, test_id);

  EXPECT_CALL(mock_log,
              Log(::logging::LOGGING_ERROR, _, _, _, HasSubstr(expected_log)));

  LOG(ERROR) << AlertLogTag(category) << test_msg << test_id;
}

}  // namespace dlcservice
