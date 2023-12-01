// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "smbprovider/constants.h"
#include "smbprovider/fake_samba_interface.h"

namespace smbprovider {

namespace {

constexpr time_t kFileDate = 123456789;

std::string GetDefaultServer() {
  return "smb://wdshare";
}

std::string GetDefaultMountRoot() {
  return "smb://wdshare/test";
}

std::string GetDefaultDirectoryPath() {
  return "smb://wdshare/test/path";
}

std::string GetDefaultFilePath() {
  return "smb://wdshare/test/dog.jpg";
}

}  // namespace

class FakeSambaTest : public testing::Test {
 public:
  FakeSambaTest() {
    fake_samba_.AddDirectory(GetDefaultServer());
    fake_samba_.AddDirectory(GetDefaultMountRoot());
  }
  FakeSambaTest(const FakeSambaTest&) = delete;
  FakeSambaTest& operator=(const FakeSambaTest&) = delete;

  ~FakeSambaTest() = default;

 protected:
  int32_t OpenCopySource(const std::string& file_path, int32_t* source_fd) {
    return fake_samba_.OpenFile(file_path, O_RDONLY, source_fd);
  }

  int32_t OpenCopyTarget(const std::string& file_path, int32_t* target_fd) {
    return fake_samba_.CreateFile(file_path, target_fd);
  }

  void CloseCopySourceAndTarget(int32_t source_fd, int32_t target_fd) {
    EXPECT_NE(0, source_fd);
    EXPECT_NE(0, target_fd);

    if (source_fd > 0) {
      fake_samba_.CloseFile(source_fd);
    }
    if (target_fd > 0) {
      fake_samba_.CloseFile(target_fd);
    }
  }

  FakeSambaInterface fake_samba_;
};

TEST_F(FakeSambaTest, FileEqualReturnsFalseOnFileThatDoesntExist) {
  EXPECT_FALSE(fake_samba_.IsFileDataEqual("smb://wdshare/invalid.jpg",
                                           std::vector<uint8_t>()));
}

TEST_F(FakeSambaTest, FileEqualReturnsFalseOnDirectory) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());
  EXPECT_FALSE(fake_samba_.IsFileDataEqual(GetDefaultDirectoryPath(),
                                           std::vector<uint8_t>()));
}

TEST_F(FakeSambaTest, FileEqualReturnsFalseOnFileWithNoData) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Should be false even if we pass in an empty vector.
  EXPECT_FALSE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(),
                                           std::vector<uint8_t>()));
}

TEST_F(FakeSambaTest, FileEqualReturnsFalseOnUnequalData) {
  const std::vector<uint8_t> file_data = {0};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);

  // Provide vector with different data.
  const std::vector<uint8_t> other_data = {1};
  EXPECT_FALSE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), other_data));
}

TEST_F(FakeSambaTest, FileEqualReturnsFalseOnSamePrefix) {
  const std::vector<uint8_t> file_data = {0, 1, 2};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);

  // Provide vector with different data but same prefix.
  const std::vector<uint8_t> other_data = {0, 1, 2, 3};
  EXPECT_FALSE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), other_data));
}

TEST_F(FakeSambaTest, FileEqualReturnsFalseOnSamePrefix2) {
  const std::vector<uint8_t> file_data = {0, 1, 2, 3};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);

  // Provide vector with different data but same prefix.
  const std::vector<uint8_t> other_data = {0, 1, 2};
  EXPECT_FALSE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), other_data));
}

TEST_F(FakeSambaTest, FileEqualReturnsTrueOnEmptyData) {
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, std::vector<uint8_t>());

  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(),
                                          std::vector<uint8_t>()));
}

TEST_F(FakeSambaTest, FileEqualReturnsTrueOnEqualData) {
  const std::vector<uint8_t> file_data = {0, 1, 2, 3};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);

  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), file_data));
}

TEST_F(FakeSambaTest, OpenFileOpensFileWithZeroSizeAndZeroOffset) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Verify that the offset and size is zero.
  EXPECT_EQ(0, fake_samba_.GetFileSize(GetDefaultFilePath()));
  EXPECT_EQ(0, fake_samba_.GetFileOffset(file_id));
}

TEST_F(FakeSambaTest, SeekCorrectlyChangesOffset) {
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Change the offset and verify it changed.
  int64_t new_offset = 2;
  EXPECT_EQ(0, fake_samba_.Seek(file_id, new_offset));
  EXPECT_EQ(new_offset, fake_samba_.GetFileOffset(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldFailIfDirectory) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());

  // Open directory.
  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));

  // Should fail writing any data to the directory.
  const std::vector<uint8_t> new_data = {'x'};
  EXPECT_EQ(EISDIR,
            fake_samba_.WriteFile(dir_id, new_data.data(), new_data.size()));

  EXPECT_EQ(0, fake_samba_.CloseDirectory(dir_id));
}

TEST_F(FakeSambaTest, WriteFileShouldFailIfNotWriteable) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Open the file with READ_ONLY permissions.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDONLY, &file_id));

  // Should fail writing any data to the file.
  const std::vector<uint8_t> new_data = {'x'};
  EXPECT_EQ(EINVAL,
            fake_samba_.WriteFile(file_id, new_data.data(), new_data.size()));

  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldChangeOffset) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Write the data into the file.
  const std::vector<uint8_t> new_data = {0, 1, 2, 3, 4, 5};
  EXPECT_EQ(0,
            fake_samba_.WriteFile(file_id, new_data.data(), new_data.size()));

  // Offset should be at the end of the written data + offset (which in this
  // case is 0).
  EXPECT_EQ(new_data.size(), fake_samba_.GetFileOffset(file_id));

  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldWriteCorrectDataWithReadWrite) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Write the data into the file.
  const std::vector<uint8_t> new_data = {0, 1, 2, 3, 4, 5};
  EXPECT_EQ(0,
            fake_samba_.WriteFile(file_id, new_data.data(), new_data.size()));

  // Read the contents of the file.
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), new_data));
  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldWriteCorrectDataWithWriteOnly) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_WRONLY, &file_id));

  // Write the data into the file.
  const std::vector<uint8_t> new_data = {0, 1, 2, 3, 4, 5};
  EXPECT_EQ(0,
            fake_samba_.WriteFile(file_id, new_data.data(), new_data.size()));

  // Read the contents of the file.
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), new_data));
  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldWriteFromOffset) {
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Change the offset to 1.
  EXPECT_EQ(0, fake_samba_.Seek(file_id, 1));

  // Write the data into the file.
  const std::vector<uint8_t> new_data = {'a', 'b'};
  EXPECT_EQ(0,
            fake_samba_.WriteFile(file_id, new_data.data(), new_data.size()));

  // Validate that the data read is the same as expected.
  const std::vector<uint8_t> expected = {0, 'a', 'b', 3, 4, 5};
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), expected));

  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldWriteToLargerSize) {
  std::vector<uint8_t> file_data = {0, 1, 2, 3};
  fake_samba_.AddFile(GetDefaultFilePath(), kFileDate, file_data);
  EXPECT_EQ(file_data.size(), fake_samba_.GetFileSize(GetDefaultFilePath()));

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Write the data into the file.
  const std::vector<uint8_t> new_data = {5, 6, 7, 8, 9, 9, 9, 9};
  EXPECT_EQ(0, fake_samba_.GetFileOffset(file_id));
  EXPECT_EQ(0,
            fake_samba_.WriteFile(file_id, new_data.data(), new_data.size()));

  // Validate that the data read is the same as expected.
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), new_data));

  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, WriteFileShouldWriteTwice) {
  fake_samba_.AddFile(GetDefaultFilePath());

  // Open the file to get a file_id.
  int32_t file_id;
  EXPECT_EQ(0, fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));

  // Do the first write.
  const std::vector<uint8_t> data1 = {1, 2, 3, 4};
  EXPECT_EQ(0, fake_samba_.GetFileOffset(file_id));
  EXPECT_EQ(0, fake_samba_.WriteFile(file_id, data1.data(), data1.size()));

  // Do the second write.
  const std::vector<uint8_t> data2 = {'a', 'b', 'c', 'd'};
  EXPECT_EQ(data1.size(), fake_samba_.GetFileOffset(file_id));
  EXPECT_EQ(0, fake_samba_.WriteFile(file_id, data2.data(), data2.size()));

  // Size of the data should be equal to the expected data.
  const std::vector<uint8_t> expected_data = {1, 2, 3, 4, 'a', 'b', 'c', 'd'};

  // Validate that the data read is the same as expected.
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(GetDefaultFilePath(), expected_data));

  EXPECT_EQ(0, fake_samba_.CloseFile(file_id));
}

TEST_F(FakeSambaTest, CreateDirectoryFailsOnMissingParentDir) {
  EXPECT_EQ(ENOENT,
            fake_samba_.CreateDirectory("smb://wdshare/test/invalid/path"));
}

TEST_F(FakeSambaTest, CreateDirectoryFailsOnExistingDir) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());
  EXPECT_EQ(EEXIST, fake_samba_.CreateDirectory(GetDefaultDirectoryPath()));
}

TEST_F(FakeSambaTest, CreateDirectoryFailsOnExistingFile) {
  fake_samba_.AddFile(GetDefaultFilePath());
  EXPECT_EQ(EEXIST, fake_samba_.CreateDirectory(GetDefaultFilePath()));
}

TEST_F(FakeSambaTest, CreateDirectorySucceedsOnValidPath) {
  EXPECT_EQ(0, fake_samba_.CreateDirectory(GetDefaultDirectoryPath()));
}

TEST_F(FakeSambaTest, UnlinkFailsOnLockedFile) {
  fake_samba_.AddLockedFile(GetDefaultFilePath());

  EXPECT_EQ(EACCES, fake_samba_.Unlink(GetDefaultFilePath()));
}

TEST_F(FakeSambaTest, RemoveDirectoryFailsOnLockedDirectory) {
  fake_samba_.AddLockedDirectory(GetDefaultDirectoryPath());

  EXPECT_EQ(EACCES, fake_samba_.RemoveDirectory(GetDefaultDirectoryPath()));
}

TEST_F(FakeSambaTest, OpenDirectoryFailsOnLockedDirectory) {
  fake_samba_.AddLockedDirectory(GetDefaultDirectoryPath());

  int32_t dir_id;
  EXPECT_EQ(EACCES,
            fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_EQ(-1, dir_id);
}

TEST_F(FakeSambaTest, GetDirectoryEntryWithMetadataEmptyDir) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_GE(dir_id, 0);

  const struct libsmb_file_info* file_info = nullptr;
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntryWithMetadata(dir_id, &file_info));
  EXPECT_EQ(nullptr, file_info);
}

TEST_F(FakeSambaTest, GetDirectoryEntryWithMetadataOneFile) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());
  const std::string filename = GetDefaultDirectoryPath() + "/file";
  const size_t expected_size = 7;

  fake_samba_.AddFile(filename, expected_size, kFileDate);

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_GE(dir_id, 0);

  const struct libsmb_file_info* file_info = nullptr;
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntryWithMetadata(dir_id, &file_info));
  EXPECT_NE(nullptr, file_info);
  EXPECT_EQ(expected_size, file_info->size);
  EXPECT_EQ(kFileDate, file_info->mtime_ts.tv_sec);
  EXPECT_EQ(0, file_info->attrs & kFileAttributeDirectory);

  // No more files.
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntryWithMetadata(dir_id, &file_info));
  EXPECT_EQ(nullptr, file_info);
}

TEST_F(FakeSambaTest, GetDirectoryEntryWithMetadataOneDirectory) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());
  const std::string directory_name = GetDefaultDirectoryPath() + "/dir";

  fake_samba_.AddDirectory(directory_name, false /* locked */, SMBC_DIR,
                           kFileDate);

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_GE(dir_id, 0);

  const struct libsmb_file_info* file_info = nullptr;
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntryWithMetadata(dir_id, &file_info));
  EXPECT_NE(nullptr, file_info);
  EXPECT_EQ(0, file_info->size);
  EXPECT_EQ(kFileDate, file_info->mtime_ts.tv_sec);
  EXPECT_EQ(kFileAttributeDirectory,
            file_info->attrs & kFileAttributeDirectory);

  // No more entries.
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntryWithMetadata(dir_id, &file_info));
  EXPECT_EQ(nullptr, file_info);
}

TEST_F(FakeSambaTest, GetDirectoryEntryWithMetadataInvalidDirId) {
  const struct libsmb_file_info* file_info;

  // Invalid dir id.
  int32_t dir_id = 0;
  EXPECT_EQ(EBADF,
            fake_samba_.GetDirectoryEntryWithMetadata(dir_id, &file_info));
}

TEST_F(FakeSambaTest, GetDirectoryEntryEmptyDir) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_GE(dir_id, 0);

  const struct smbc_dirent* dirent = nullptr;
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntry(dir_id, &dirent));
  EXPECT_EQ(nullptr, dirent);
}

TEST_F(FakeSambaTest, GetDirectoryEntryOneFile) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());
  const std::string filename = GetDefaultDirectoryPath() + "/file";
  const size_t expected_size = 7;

  fake_samba_.AddFile(filename, expected_size, kFileDate);

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_GE(dir_id, 0);

  const struct smbc_dirent* dirent = nullptr;
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntry(dir_id, &dirent));
  EXPECT_NE(nullptr, dirent);
  EXPECT_EQ(SMBC_FILE, dirent->smbc_type);

  // No more files.
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntry(dir_id, &dirent));
  EXPECT_EQ(nullptr, dirent);
}

TEST_F(FakeSambaTest, GetDirectoryEntryOneDirectory) {
  fake_samba_.AddDirectory(GetDefaultDirectoryPath());
  const std::string directory_name = GetDefaultDirectoryPath() + "/dir";

  fake_samba_.AddDirectory(directory_name, false /* locked */, SMBC_DIR,
                           kFileDate);

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory(GetDefaultDirectoryPath(), &dir_id));
  EXPECT_GE(dir_id, 0);

  const struct smbc_dirent* dirent = nullptr;
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntry(dir_id, &dirent));
  EXPECT_NE(nullptr, dirent);
  EXPECT_EQ(SMBC_DIR, dirent->smbc_type);

  // No more entries.
  EXPECT_EQ(0, fake_samba_.GetDirectoryEntry(dir_id, &dirent));
  EXPECT_EQ(nullptr, dirent);
}

TEST_F(FakeSambaTest, GetDirectoryEntryInvalidDirId) {
  const struct smbc_dirent* dirent;

  // Invalid dir id.
  int32_t dir_id = 0;
  EXPECT_EQ(EBADF, fake_samba_.GetDirectoryEntry(dir_id, &dirent));
}

TEST_F(FakeSambaTest, GetEntryStatusFailsOnLockedEntries) {
  fake_samba_.AddLockedDirectory(GetDefaultDirectoryPath());
  fake_samba_.AddLockedFile(GetDefaultFilePath());

  struct stat stat_info;
  EXPECT_EQ(EACCES,
            fake_samba_.GetEntryStatus(GetDefaultDirectoryPath(), &stat_info));
  EXPECT_EQ(EACCES,
            fake_samba_.GetEntryStatus(GetDefaultFilePath(), &stat_info));
}

TEST_F(FakeSambaTest, OpenFileFailsOnLockedFile) {
  fake_samba_.AddLockedFile(GetDefaultFilePath());

  int32_t file_id;
  EXPECT_EQ(EACCES,
            fake_samba_.OpenFile(GetDefaultFilePath(), O_RDWR, &file_id));
}

// Deleting an entry before the current entry does not move the current entry.
TEST_F(FakeSambaTest, DeleteBeforeCurrent) {
  fake_samba_.AddDirectory("smb://wdshare/test/path");
  fake_samba_.AddFile("smb://wdshare/test/path/dog.jpg");
  fake_samba_.AddFile("smb://wdshare/test/path/cat.txt");
  fake_samba_.AddFile("smb://wdshare/test/path/mouse.txt");

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory("smb://wdshare/test/path", &dir_id));
  fake_samba_.SetCurrentEntry(dir_id, 1);
  EXPECT_EQ("cat.txt", fake_samba_.GetCurrentEntry(dir_id));

  EXPECT_EQ(0, fake_samba_.Unlink("smb://wdshare/test/path/dog.jpg"));
  EXPECT_EQ("cat.txt", fake_samba_.GetCurrentEntry(dir_id));
}

// Deleting an entry after the current entry does not move the current entry.
TEST_F(FakeSambaTest, DeleteAfterCurrent) {
  fake_samba_.AddDirectory("smb://wdshare/test/path");
  fake_samba_.AddFile("smb://wdshare/test/path/dog.jpg");
  fake_samba_.AddFile("smb://wdshare/test/path/cat.txt");
  fake_samba_.AddFile("smb://wdshare/test/path/mouse.txt");

  int32_t dir_id;
  EXPECT_EQ(0, fake_samba_.OpenDirectory("smb://wdshare/test/path", &dir_id));
  fake_samba_.SetCurrentEntry(dir_id, 1);
  EXPECT_EQ("cat.txt", fake_samba_.GetCurrentEntry(dir_id));

  EXPECT_EQ(0, fake_samba_.Unlink("smb://wdshare/test/path/mouse.txt"));
  EXPECT_EQ("cat.txt", fake_samba_.GetCurrentEntry(dir_id));
}

TEST_F(FakeSambaTest, MoveEntryFailsWhenSrcIsNotDirAndTargetIsDir) {
  const std::string file_path = "smb://wdshare/test/dog.jpg";
  const std::string dir_path = "smb://wdshare/test/cats";

  fake_samba_.AddFile(file_path);
  fake_samba_.AddDirectory(dir_path);

  EXPECT_EQ(EISDIR, fake_samba_.MoveEntry(file_path, dir_path));
}

TEST_F(FakeSambaTest, MoveEntryFailsWhenSrcIsDirAndTargetIsNonEmptyDir) {
  const std::string src_dir_path = "smb://wdshare/test/cats";
  const std::string dst_dir_path = "smb://wdshare/test/dogs";

  fake_samba_.AddDirectory(src_dir_path);
  fake_samba_.AddDirectory(dst_dir_path);
  fake_samba_.AddFile(dst_dir_path + "/dog1.jpg");

  EXPECT_EQ(EEXIST, fake_samba_.MoveEntry(src_dir_path, dst_dir_path));
}

TEST_F(FakeSambaTest, MoveEntryFailsWhenSrcIsFileAndDstIsExistingFile) {
  const std::string src_path = "smb://wdshare/test/dog.jpg";
  const std::string dst_path = "smb://wdshare/test/cat.txt";

  fake_samba_.AddFile(src_path);
  fake_samba_.AddFile(dst_path);

  EXPECT_EQ(EEXIST, fake_samba_.MoveEntry(src_path, dst_path));
}

// MoveEntry should fail when attempting to make a directory a subdirectory of
// itself.
TEST_F(FakeSambaTest, MoveEntryFailsWhenDstIsSubDirectoryOfSrc) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");

  EXPECT_EQ(EINVAL, fake_samba_.MoveEntry("smb://wdshare/test/dogs",
                                          "smb://wdshare/test/dogs/cats"));
}

TEST_F(FakeSambaTest, MoveEntryFailsWhenSrcIsDirAndDstExistsAndIsFile) {
  const std::string file_path = "smb://wdshare/test/dog.jpg";
  const std::string dir_path = "smb://wdshare/test/cats";

  fake_samba_.AddFile(file_path);
  fake_samba_.AddDirectory(dir_path);

  EXPECT_EQ(ENOTDIR, fake_samba_.MoveEntry(dir_path, file_path));
}

TEST_F(FakeSambaTest, MoveEntryFailsWhenDstParentIsLocked) {
  fake_samba_.AddFile("smb://wdshare/test/dog.jpg");
  fake_samba_.AddLockedDirectory("smb://wdshare/test/locked");

  EXPECT_EQ(EACCES, fake_samba_.MoveEntry("smb://wdshare/test/dog.jpg",
                                          "smb://wdshare/test/locked/dog.jpg"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyRenamesDirectory) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/dogs",
                                     "smb://wdshare/test/cats"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/cats"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyRenamesDirectoryWithAppendedPath) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/dogs",
                                     "smb://wdshare/test/dogs123"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/dogs123"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyMovesEmptyDirectoryIntoDirectory) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");
  fake_samba_.AddDirectory("smb://wdshare/test/cats");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/dogs",
                                     "smb://wdshare/test/cats/dogs"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/cats/dogs"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyMovesNonEmptyDirectory) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");
  fake_samba_.AddFile("smb://wdshare/test/dogs/1.jpg");
  fake_samba_.AddDirectory("smb://wdshare/test/cats");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/dogs",
                                     "smb://wdshare/test/cats/dogs"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs"));
  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs/1.jpg"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/cats/dogs"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/cats/dogs/1.jpg"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyMovesFileIntoDirectory) {
  fake_samba_.AddFile("smb://wdshare/test/1.jpg");
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/1.jpg",
                                     "smb://wdshare/test/dogs/1.jpg"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/1.jpg"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/dogs/1.jpg"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyRenamesFile) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");
  fake_samba_.AddFile("smb://wdshare/test/dogs/1.txt");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/dogs/1.txt",
                                     "smb://wdshare/test/dogs/2.jpg"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs/1.txt"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/dogs/2.jpg"));
}

TEST_F(FakeSambaTest, MoveEntrySuccessfullyRenamesFileIntoDirectory) {
  fake_samba_.AddDirectory("smb://wdshare/test/dogs");
  fake_samba_.AddDirectory("smb://wdshare/test/cats");
  fake_samba_.AddFile("smb://wdshare/test/dogs/1.txt");

  EXPECT_EQ(0, fake_samba_.MoveEntry("smb://wdshare/test/dogs/1.txt",
                                     "smb://wdshare/test/cats/2.jpg"));

  EXPECT_FALSE(fake_samba_.EntryExists("smb://wdshare/test/dogs/1.txt"));
  EXPECT_TRUE(fake_samba_.EntryExists("smb://wdshare/test/cats/2.jpg"));
}

TEST_F(FakeSambaTest, MoveEntryFailsToMoveLockedDirectory) {
  fake_samba_.AddLockedDirectory("smb://wdshare/test/dogs");
  fake_samba_.AddDirectory("smb://wdshare/test/cats");

  EXPECT_EQ(EACCES, fake_samba_.MoveEntry("smb://wdshare/test/dogs",
                                          "smb://wdshare/test/cats/dogs"));
}

// CopyFile should succeed when the source file exists, the destination file
// does not exist, but the destination directory does.
TEST_F(FakeSambaTest, CopyFileWithDataSucceeds) {
  const std::string source_dir = "smb://wdshare/test/source";
  const std::string source_file = source_dir + "/source.txt";
  const std::string target_dir = "smb://wdshare/test/target";
  const std::string target_file = target_dir + "/target.txt";

  fake_samba_.AddDirectory(source_dir);
  fake_samba_.AddDirectory(target_dir);
  const std::vector<uint8_t> data = {0, 1, 2, 3};
  fake_samba_.AddFile(source_file, kFileDate, data);

  EXPECT_FALSE(fake_samba_.EntryExists(target_file));
  EXPECT_EQ(0, fake_samba_.CopyFile(source_file, target_file));

  // Verify the target file was created correctly.
  EXPECT_TRUE(fake_samba_.EntryExists(target_file));
  EXPECT_EQ(data.size(), fake_samba_.GetFileSize(target_file));
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(target_file, data));

  // Verify the source file is still there.
  EXPECT_TRUE(fake_samba_.EntryExists(source_file));
  EXPECT_EQ(data.size(), fake_samba_.GetFileSize(source_file));
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(source_file, data));
}

// CopyFile without file data should succeed when the source file exists,
// the destination file does not exist, but the destination directory does.
TEST_F(FakeSambaTest, CopyFileWithoutDataSucceeds) {
  const std::string source_dir = "smb://wdshare/test/source";
  const std::string source_file = source_dir + "/source.txt";
  const std::string target_dir = "smb://wdshare/test/target";
  const std::string target_file = target_dir + "/target.txt";

  fake_samba_.AddDirectory(source_dir);
  fake_samba_.AddDirectory(target_dir);
  const size_t file_size = 12345;
  fake_samba_.AddFile(source_file, file_size, kFileDate, false /* locked */);

  EXPECT_FALSE(fake_samba_.EntryExists(target_file));
  EXPECT_EQ(0, fake_samba_.CopyFile(source_file, target_file));

  // Verify the target file was created correctly.
  EXPECT_TRUE(fake_samba_.EntryExists(target_file));
  EXPECT_EQ(file_size, fake_samba_.GetFileSize(target_file));

  // Verify the source file is still there.
  EXPECT_TRUE(fake_samba_.EntryExists(source_file));
  EXPECT_EQ(file_size, fake_samba_.GetFileSize(source_file));
}

// CopyFile should fail when the source file does not exist.
TEST_F(FakeSambaTest, CopyFailsWhenSourceDoesNotExist) {
  const std::string target_dir = "smb://wdshare/test/target";
  const std::string target_file = "smb://wdshare/test/target/file.txt";

  fake_samba_.AddDirectory(target_dir);

  EXPECT_EQ(ENOENT, fake_samba_.CopyFile("smb://wdshare/test/source/file.txt",
                                         target_file));
}

// CopyFile should fail if the destination file exists.
TEST_F(FakeSambaTest, CopyFailsWhenDestinationFileExists) {
  const std::string source_dir = "smb://wdshare/test/source";
  const std::string source_file = source_dir + "/source.txt";
  const std::string target_dir = "smb://wdshare/test/target";
  const std::string target_file = target_dir + "/target.txt";

  fake_samba_.AddDirectory(source_dir);
  fake_samba_.AddDirectory(target_dir);
  fake_samba_.AddFile(source_file);
  fake_samba_.AddFile(target_file);

  EXPECT_EQ(EEXIST, fake_samba_.CopyFile(source_file, target_file));
}

// CopyFile should fail if the destination directory exists. The
// destination must be a path to the file, not just a directory.
TEST_F(FakeSambaTest, CopyFailsWhenDestinationDirExists) {
  const std::string source_dir = "smb://wdshare/test/source";
  const std::string source_file = source_dir + "/source.txt";
  const std::string target_dir = "smb://wdshare/test/target";

  fake_samba_.AddDirectory(source_dir);
  fake_samba_.AddDirectory(target_dir);
  fake_samba_.AddFile(source_file);

  EXPECT_EQ(EEXIST, fake_samba_.CopyFile(source_file, target_dir));
}

// CopyFile should fail if the parent directory of the destination
// does not exist.
TEST_F(FakeSambaTest, CopyFailsWhenDestinationParentDirDoesNotExist) {
  const std::string source_dir = "smb://wdshare/test/source";
  const std::string source_file = source_dir + "/source.txt";
  const std::string target_dir = "smb://wdshare/test/target";
  const std::string target_file = target_dir + "/target.txt";

  fake_samba_.AddDirectory(source_dir);
  fake_samba_.AddFile(source_file);

  EXPECT_EQ(ENOENT, fake_samba_.CopyFile(source_file, target_file));
}

// CopyFile should fail if the parent directory of the destination
// does not exist.
TEST_F(FakeSambaTest, CopyFailsWhenDestinationDirLocked) {
  const std::string source_dir = "smb://wdshare/test/source";
  const std::string source_file = source_dir + "/source.txt";
  const std::string target_dir = "smb://wdshare/test/target";
  const std::string target_file = target_dir + "/target.txt";

  fake_samba_.AddDirectory(source_dir);
  fake_samba_.AddFile(source_file);
  fake_samba_.AddLockedDirectory(target_dir);

  EXPECT_EQ(EACCES, fake_samba_.CopyFile(source_file, target_file));
}

TEST_F(FakeSambaTest, SpliceFileCorrectlySplicesFullFile) {
  // Create a source file.
  const std::string source_path = "smb://wdshare/test/source";
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(source_path, 0 /* date */, file_data);

  const std::string target_path = "smb://wdshare/test/target";

  // Open source and target.
  int32_t source_fd;
  EXPECT_EQ(0, OpenCopySource(source_path, &source_fd));

  int32_t target_fd;
  EXPECT_EQ(0, OpenCopyTarget(target_path, &target_fd));

  // Splice all of the source to the destination.
  off_t bytes_written;
  EXPECT_EQ(0, fake_samba_.SpliceFile(source_fd, target_fd, file_data.size(),
                                      &bytes_written));
  EXPECT_EQ(file_data.size(), bytes_written);

  EXPECT_TRUE(fake_samba_.IsFileDataEqual(target_path, file_data));

  CloseCopySourceAndTarget(source_fd, target_fd);
}

TEST_F(FakeSambaTest, SpliceFileCorrectlySplicePartialCopiedFile) {
  // Create a source file
  const std::string source_path = "smb://wdshare/test/source";
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(source_path, 0 /* date */, file_data);

  const std::string target_path = "smb://wdshare/test/target";

  // Open source and target.
  int32_t source_fd;
  EXPECT_EQ(0, OpenCopySource(source_path, &source_fd));

  int32_t target_fd;
  EXPECT_EQ(0, OpenCopyTarget(target_path, &target_fd));

  // Splice part of the source to the destination.
  const off_t bytes_to_splice = 3;
  off_t bytes_written;
  EXPECT_EQ(0, fake_samba_.SpliceFile(source_fd, target_fd, bytes_to_splice,
                                      &bytes_written));
  EXPECT_EQ(bytes_to_splice, bytes_written);

  std::vector<uint8_t> expected_splice_data(
      file_data.begin(), file_data.begin() + bytes_to_splice);
  EXPECT_TRUE(fake_samba_.IsFileDataEqual(target_path, expected_splice_data));

  CloseCopySourceAndTarget(source_fd, target_fd);
}

TEST_F(FakeSambaTest, SpliceFileCorrectlySplicesMultipleChunks) {
  // Create a source file
  const std::string source_path = "smb://wdshare/test/source";
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(source_path, 0 /* date */, file_data);

  const std::string target_path = "smb://wdshare/test/target";

  // Open source and target.
  int32_t source_fd;
  EXPECT_EQ(0, OpenCopySource(source_path, &source_fd));

  int32_t target_fd;
  EXPECT_EQ(0, OpenCopyTarget(target_path, &target_fd));

  // Splice all of the source to the destination in two chunks.
  const off_t bytes_to_splice = 3;
  off_t bytes_written;
  EXPECT_EQ(0, fake_samba_.SpliceFile(source_fd, target_fd, bytes_to_splice,
                                      &bytes_written));
  EXPECT_EQ(bytes_to_splice, bytes_written);
  EXPECT_EQ(0, fake_samba_.SpliceFile(source_fd, target_fd, bytes_to_splice,
                                      &bytes_written));
  EXPECT_EQ(bytes_to_splice, bytes_written);

  EXPECT_TRUE(fake_samba_.IsFileDataEqual(target_path, file_data));

  CloseCopySourceAndTarget(source_fd, target_fd);
}

TEST_F(FakeSambaTest, SpliceFileReturnsEBADFIfSourceIsNotOpened) {
  // Create a source file
  const std::string source_path = "smb://wdshare/test/source";
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(source_path, 0 /* date */, file_data);

  const std::string target_path = "smb://wdshare/test/target";

  // Open source.
  int32_t source_fd;
  EXPECT_EQ(0, OpenCopySource(source_path, &source_fd));

  const int32_t invalid_target_fd = 95;

  off_t bytes_written;
  EXPECT_EQ(EBADF, fake_samba_.SpliceFile(source_fd, invalid_target_fd,
                                          file_data.size(), &bytes_written));
}

TEST_F(FakeSambaTest, SpliceFileReturnsEBADFIfTargetIsNotOpened) {
  // Create a source file
  const std::string source_path = "smb://wdshare/test/source";
  std::vector<uint8_t> file_data = {0, 1, 2, 3, 4, 5};
  fake_samba_.AddFile(source_path, 0 /* date */, file_data);

  const std::string target_path = "smb://wdshare/test/target";

  // Open target.
  const int32_t invalid_source_fd = 96;

  int32_t target_fd;
  EXPECT_EQ(0, OpenCopyTarget(target_path, &target_fd));

  off_t bytes_written;
  EXPECT_EQ(EBADF, fake_samba_.SpliceFile(invalid_source_fd, target_fd,
                                          file_data.size(), &bytes_written));
}

}  // namespace smbprovider
