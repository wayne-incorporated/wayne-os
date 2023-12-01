// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/file_utils.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iterator>
#include <string>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

namespace brillo {

namespace {

constexpr int kPermissions600 =
    base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;
constexpr int kPermissions700 = base::FILE_PERMISSION_USER_MASK;
constexpr int kPermissions777 = base::FILE_PERMISSION_MASK;
constexpr int kPermissions755 = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

std::string GetRandomSuffix() {
  const int kBufferSize = 6;
  unsigned char buffer[kBufferSize];
  base::RandBytes(buffer, std::size(buffer));
  return base::HexEncode(buffer, std::size(buffer));
}

bool IsNonBlockingFD(int fd) {
  return fcntl(fd, F_GETFL) & O_NONBLOCK;
}

}  // namespace

class FileUtilsTest : public testing::Test {
 public:
  FileUtilsTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    file_path_ = temp_dir_.GetPath().Append("test.temp");
  }

 protected:
  base::FilePath file_path_;
  base::ScopedTempDir temp_dir_;

  // Writes |contents| to |file_path_|. Pulled into a separate function just
  // to improve readability of tests.
  void WriteFile(const std::string& contents) {
    EXPECT_EQ(contents.length(),
              base::WriteFile(file_path_, contents.c_str(), contents.length()));
  }

  // Verifies that the file at |file_path_| exists and contains |contents|.
  void ExpectFileContains(const std::string& contents) {
    EXPECT_TRUE(base::PathExists(file_path_));
    std::string new_contents;
    EXPECT_TRUE(base::ReadFileToString(file_path_, &new_contents));
    EXPECT_EQ(contents, new_contents);
  }

  // Verifies that the file at |file_path_| has |permissions|.
  void ExpectFilePermissions(int permissions) {
    int actual_permissions;
    EXPECT_TRUE(base::GetPosixFilePermissions(file_path_, &actual_permissions));
    EXPECT_EQ(permissions, actual_permissions);
  }

  // Creates a file with a random name in the temporary directory.
  base::FilePath GetTempName() {
    return temp_dir_.GetPath().Append(GetRandomSuffix());
  }
};

TEST_F(FileUtilsTest, TouchFileCreate) {
  EXPECT_TRUE(TouchFile(file_path_));
  ExpectFileContains("");
  ExpectFilePermissions(kPermissions600);
}

TEST_F(FileUtilsTest, TouchFileCreateThroughUmask) {
  mode_t old_umask = umask(kPermissions777);
  EXPECT_TRUE(TouchFile(file_path_));
  umask(old_umask);
  ExpectFileContains("");
  ExpectFilePermissions(kPermissions600);
}

TEST_F(FileUtilsTest, TouchFileCreateDirectoryStructure) {
  file_path_ = temp_dir_.GetPath().Append("foo/bar/baz/test.temp");
  EXPECT_TRUE(TouchFile(file_path_));
  ExpectFileContains("");
}

TEST_F(FileUtilsTest, TouchFileExisting) {
  WriteFile("abcd");
  EXPECT_TRUE(TouchFile(file_path_));
  ExpectFileContains("abcd");
}

TEST_F(FileUtilsTest, TouchFileReplaceDirectory) {
  EXPECT_TRUE(base::CreateDirectory(file_path_));
  EXPECT_TRUE(TouchFile(file_path_));
  EXPECT_FALSE(base::DirectoryExists(file_path_));
  ExpectFileContains("");
}

TEST_F(FileUtilsTest, TouchFileReplaceSymlink) {
  base::FilePath symlink_target = temp_dir_.GetPath().Append("target.temp");
  EXPECT_TRUE(base::CreateSymbolicLink(symlink_target, file_path_));
  EXPECT_TRUE(TouchFile(file_path_));
  EXPECT_FALSE(base::IsLink(file_path_));
  ExpectFileContains("");
}

TEST_F(FileUtilsTest, TouchFileReplaceOtherUser) {
  WriteFile("abcd");
  EXPECT_TRUE(TouchFile(file_path_, kPermissions777, geteuid() + 1, getegid()));
  ExpectFileContains("");
}

TEST_F(FileUtilsTest, TouchFileReplaceOtherGroup) {
  WriteFile("abcd");
  EXPECT_TRUE(TouchFile(file_path_, kPermissions777, geteuid(), getegid() + 1));
  ExpectFileContains("");
}

TEST_F(FileUtilsTest, TouchFileCreateWithAllPermissions) {
  EXPECT_TRUE(TouchFile(file_path_, kPermissions777, geteuid(), getegid()));
  ExpectFileContains("");
  ExpectFilePermissions(kPermissions777);
}

TEST_F(FileUtilsTest, TouchFileCreateWithOwnerPermissions) {
  EXPECT_TRUE(TouchFile(file_path_, kPermissions700, geteuid(), getegid()));
  ExpectFileContains("");
  ExpectFilePermissions(kPermissions700);
}

TEST_F(FileUtilsTest, TouchFileExistingPermissionsUnchanged) {
  EXPECT_TRUE(TouchFile(file_path_, kPermissions777, geteuid(), getegid()));
  EXPECT_TRUE(TouchFile(file_path_, kPermissions700, geteuid(), getegid()));
  ExpectFileContains("");
  ExpectFilePermissions(kPermissions777);
}

// Other parts of OpenSafely are tested in Arcsetup.TestInstallDirectory*.
TEST_F(FileUtilsTest, TestOpenSafelyWithoutNonblocking) {
  ASSERT_TRUE(TouchFile(file_path_, kPermissions700, geteuid(), getegid()));
  base::ScopedFD fd(OpenSafely(file_path_, O_RDONLY, 0));
  EXPECT_TRUE(fd.is_valid());
  EXPECT_FALSE(IsNonBlockingFD(fd.get()));
}

TEST_F(FileUtilsTest, TestOpenSafelyWithNonblocking) {
  ASSERT_TRUE(TouchFile(file_path_, kPermissions700, geteuid(), getegid()));
  base::ScopedFD fd = OpenSafely(file_path_, O_RDONLY | O_NONBLOCK, 0);
  EXPECT_TRUE(fd.is_valid());
  EXPECT_TRUE(IsNonBlockingFD(fd.get()));
}

TEST_F(FileUtilsTest, TestOpenFifoSafelySuccess) {
  ASSERT_EQ(0, mkfifo(file_path_.value().c_str(), kPermissions700));
  base::ScopedFD fd(OpenFifoSafely(file_path_, O_RDONLY, 0));
  EXPECT_TRUE(fd.is_valid());
  EXPECT_FALSE(IsNonBlockingFD(fd.get()));
}

TEST_F(FileUtilsTest, TestOpenFifoSafelyRegularFile) {
  ASSERT_TRUE(TouchFile(file_path_, kPermissions700, geteuid(), getegid()));
  base::ScopedFD fd = OpenFifoSafely(file_path_, O_RDONLY, 0);
  EXPECT_FALSE(fd.is_valid());
}

TEST_F(FileUtilsTest, TestMkdirRecursivelyRoot) {
  // Try to create an existing directory ("/") should still succeed.
  EXPECT_TRUE(
      MkdirRecursively(base::FilePath("/"), kPermissions755).is_valid());
}

TEST_F(FileUtilsTest, TestMkdirRecursivelySuccess) {
  // Set |temp_directory| to 0707.
  EXPECT_TRUE(base::SetPosixFilePermissions(temp_dir_.GetPath(), 0707));

  EXPECT_TRUE(
      MkdirRecursively(temp_dir_.GetPath().Append("a/b/c"), kPermissions755)
          .is_valid());
  // Confirm the 3 directories are there.
  EXPECT_TRUE(base::DirectoryExists(temp_dir_.GetPath().Append("a")));
  EXPECT_TRUE(base::DirectoryExists(temp_dir_.GetPath().Append("a/b")));
  EXPECT_TRUE(base::DirectoryExists(temp_dir_.GetPath().Append("a/b/c")));

  // Confirm that the newly created directories have 0755 mode.
  int mode = 0;
  EXPECT_TRUE(
      base::GetPosixFilePermissions(temp_dir_.GetPath().Append("a"), &mode));
  EXPECT_EQ(kPermissions755, mode);
  mode = 0;
  EXPECT_TRUE(
      base::GetPosixFilePermissions(temp_dir_.GetPath().Append("a/b"), &mode));
  EXPECT_EQ(kPermissions755, mode);
  mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(temp_dir_.GetPath().Append("a/b/c"),
                                            &mode));
  EXPECT_EQ(kPermissions755, mode);

  // Confirm that the existing directory |temp_directory| still has 0707 mode.
  mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(temp_dir_.GetPath(), &mode));
  EXPECT_EQ(0707, mode);

  // Call the API again which should still succeed.
  EXPECT_TRUE(
      MkdirRecursively(temp_dir_.GetPath().Append("a/b/c"), kPermissions755)
          .is_valid());
  EXPECT_TRUE(
      MkdirRecursively(temp_dir_.GetPath().Append("a/b/c/d"), kPermissions755)
          .is_valid());
  EXPECT_TRUE(base::DirectoryExists(temp_dir_.GetPath().Append("a/b/c/d")));
  mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(
      temp_dir_.GetPath().Append("a/b/c/d"), &mode));
  EXPECT_EQ(kPermissions755, mode);

  // Call the API again which should still succeed.
  EXPECT_TRUE(
      MkdirRecursively(temp_dir_.GetPath().Append("a/b"), kPermissions755)
          .is_valid());
  EXPECT_TRUE(MkdirRecursively(temp_dir_.GetPath().Append("a"), kPermissions755)
                  .is_valid());
}

TEST_F(FileUtilsTest, TestMkdirRecursivelyRelativePath) {
  // Try to pass a relative or empty directory. They should all fail.
  EXPECT_FALSE(
      MkdirRecursively(base::FilePath("foo"), kPermissions755).is_valid());
  EXPECT_FALSE(
      MkdirRecursively(base::FilePath("bar/"), kPermissions755).is_valid());
  EXPECT_FALSE(MkdirRecursively(base::FilePath(), kPermissions755).is_valid());
}

TEST_F(FileUtilsTest, WriteFileCanBeReadBack) {
  const base::FilePath filename(GetTempName());
  const std::string content("blablabla");
  EXPECT_TRUE(WriteStringToFile(filename, content));
  std::string output;
  EXPECT_TRUE(ReadFileToString(filename, &output));
  EXPECT_EQ(content, output);
}

TEST_F(FileUtilsTest, WriteFileSets0666) {
  const mode_t mask = 0000;
  const mode_t mode = 0666;
  const base::FilePath filename(GetTempName());
  const std::string content("blablabla");
  const mode_t old_mask = umask(mask);
  EXPECT_TRUE(WriteStringToFile(filename, content));
  int file_mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(filename, &file_mode));
  EXPECT_EQ(mode & ~mask, file_mode & 0777);
  umask(old_mask);
}

TEST_F(FileUtilsTest, WriteFileCreatesMissingParentDirectoriesWith0700) {
  const mode_t mask = 0000;
  const mode_t mode = 0700;
  const base::FilePath dirname(GetTempName());
  const base::FilePath subdirname(dirname.Append(GetRandomSuffix()));
  const base::FilePath filename(subdirname.Append(GetRandomSuffix()));
  const std::string content("blablabla");
  EXPECT_TRUE(WriteStringToFile(filename, content));
  int dir_mode = 0;
  int subdir_mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(dirname, &dir_mode));
  EXPECT_TRUE(base::GetPosixFilePermissions(subdirname, &subdir_mode));
  EXPECT_EQ(mode & ~mask, dir_mode & 0777);
  EXPECT_EQ(mode & ~mask, subdir_mode & 0777);
  const mode_t old_mask = umask(mask);
  umask(old_mask);
}

TEST_F(FileUtilsTest, WriteToFileAtomicCanBeReadBack) {
  const base::FilePath filename(GetTempName());
  const std::string content("blablabla");
  EXPECT_TRUE(
      WriteToFileAtomic(filename, content.data(), content.size(), 0644));
  std::string output;
  EXPECT_TRUE(ReadFileToString(filename, &output));
  EXPECT_EQ(content, output);
}

TEST_F(FileUtilsTest, WriteToFileAtomicHonorsMode) {
  const mode_t mask = 0000;
  const mode_t mode = 0616;
  const base::FilePath filename(GetTempName());
  const std::string content("blablabla");
  const mode_t old_mask = umask(mask);
  EXPECT_TRUE(
      WriteToFileAtomic(filename, content.data(), content.size(), mode));
  int file_mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(filename, &file_mode));
  EXPECT_EQ(mode & ~mask, file_mode & 0777);
  umask(old_mask);
}

TEST_F(FileUtilsTest, WriteToFileAtomicHonorsUmask) {
  const mode_t mask = 0073;
  const mode_t mode = 0777;
  const base::FilePath filename(GetTempName());
  const std::string content("blablabla");
  const mode_t old_mask = umask(mask);
  EXPECT_TRUE(
      WriteToFileAtomic(filename, content.data(), content.size(), mode));
  int file_mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(filename, &file_mode));
  EXPECT_EQ(mode & ~mask, file_mode & 0777);
  umask(old_mask);
}

TEST_F(FileUtilsTest,
       WriteToFileAtomicCreatesMissingParentDirectoriesWith0700) {
  const mode_t mask = 0000;
  const mode_t mode = 0700;
  const base::FilePath dirname(GetTempName());
  const base::FilePath subdirname(dirname.Append(GetRandomSuffix()));
  const base::FilePath filename(subdirname.Append(GetRandomSuffix()));
  const std::string content("blablabla");
  EXPECT_TRUE(
      WriteToFileAtomic(filename, content.data(), content.size(), 0777));
  int dir_mode = 0;
  int subdir_mode = 0;
  EXPECT_TRUE(base::GetPosixFilePermissions(dirname, &dir_mode));
  EXPECT_TRUE(base::GetPosixFilePermissions(subdirname, &subdir_mode));
  EXPECT_EQ(mode & ~mask, dir_mode & 0777);
  EXPECT_EQ(mode & ~mask, subdir_mode & 0777);
  const mode_t old_mask = umask(mask);
  umask(old_mask);
}

TEST_F(FileUtilsTest, ComputeDirectoryDiskUsageNormalRandomFile) {
  // 2MB test file.
  constexpr size_t kFileSize = 2 * 1024 * 1024;

  const base::FilePath dirname(GetTempName());
  EXPECT_TRUE(base::CreateDirectory(dirname));
  const base::FilePath filename = dirname.Append("test.temp");

  std::string file_content = base::RandBytesAsString(kFileSize);
  EXPECT_TRUE(WriteStringToFile(filename, file_content));

  int64_t result_usage = ComputeDirectoryDiskUsage(dirname);
  int64_t result_size = base::ComputeDirectorySize(dirname);

  // result_usage (what we are testing here) should be within +/-10% of ground
  // truth. The variation is to account for filesystem overhead variations.
  EXPECT_GT(result_usage, kFileSize / 10 * 9);
  EXPECT_LT(result_usage, kFileSize / 10 * 11);

  // result_usage should be close to result_size, because the test file is
  // random so it's disk usage should be similar to apparent size.
  EXPECT_GT(result_usage, result_size / 10 * 9);
  EXPECT_LT(result_usage, result_size / 10 * 11);
}

TEST_F(FileUtilsTest, ComputeDirectoryDiskUsageDeepRandomFile) {
  // 2MB test file.
  constexpr size_t kFileSize = 2 * 1024 * 1024;

  const base::FilePath dirname(GetTempName());
  EXPECT_TRUE(base::CreateDirectory(dirname));
  base::FilePath currentlevel = dirname;
  for (int i = 0; i < 10; i++) {
    base::FilePath nextlevel = currentlevel.Append("test.dir");
    EXPECT_TRUE(base::CreateDirectory(nextlevel));
    currentlevel = nextlevel;
  }
  const base::FilePath filename = currentlevel.Append("test.temp");

  std::string file_content = base::RandBytesAsString(kFileSize);
  EXPECT_TRUE(WriteStringToFile(filename, file_content));

  int64_t result_usage = ComputeDirectoryDiskUsage(dirname);
  int64_t result_size = base::ComputeDirectorySize(dirname);

  // result_usage (what we are testing here) should be within +/-10% of ground
  // truth. The variation is to account for filesystem overhead variations.
  EXPECT_GT(result_usage, kFileSize / 10 * 9);
  EXPECT_LT(result_usage, kFileSize / 10 * 11);

  // result_usage should be close to result_size, because the test file is
  // random so it's disk usage should be similar to apparent size.
  EXPECT_GT(result_usage, result_size / 10 * 9);
  EXPECT_LT(result_usage, result_size / 10 * 11);
}

TEST_F(FileUtilsTest, ComputeDirectoryDiskUsageHiddenRandomFile) {
  // 2MB test file.
  constexpr size_t kFileSize = 2 * 1024 * 1024;

  const base::FilePath dirname(GetTempName());
  EXPECT_TRUE(base::CreateDirectory(dirname));
  // File name starts with a dot, so it's a hidden file.
  const base::FilePath filename = dirname.Append(".test.temp");

  std::string file_content = base::RandBytesAsString(kFileSize);
  EXPECT_TRUE(WriteStringToFile(filename, file_content));

  int64_t result_usage = ComputeDirectoryDiskUsage(dirname);
  int64_t result_size = base::ComputeDirectorySize(dirname);

  // result_usage (what we are testing here) should be within +/-10% of ground
  // truth. The variation is to account for filesystem overhead variations.
  EXPECT_GT(result_usage, kFileSize / 10 * 9);
  EXPECT_LT(result_usage, kFileSize / 10 * 11);

  // result_usage should be close to result_size, because the test file is
  // random so it's disk usage should be similar to apparent size.
  EXPECT_GT(result_usage, result_size / 10 * 9);
  EXPECT_LT(result_usage, result_size / 10 * 11);
}

TEST_F(FileUtilsTest, ComputeDirectoryDiskUsageSparseFile) {
  // 128MB sparse test file.
  constexpr size_t kFileSize = 128 * 1024 * 1024;
  constexpr size_t kFileSizeThreshold = 64 * 1024;

  const base::FilePath dirname(GetTempName());
  EXPECT_TRUE(base::CreateDirectory(dirname));
  const base::FilePath filename = dirname.Append("test.temp");

  int fd =
      open(filename.value().c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  EXPECT_NE(fd, -1);
  // Calling ftruncate on an empty file will create a sparse file.
  EXPECT_EQ(0, ftruncate(fd, kFileSize));

  int64_t result_usage = ComputeDirectoryDiskUsage(dirname);
  int64_t result_size = base::ComputeDirectorySize(dirname);

  // result_usage (what we are testing here) should be less than
  // kFileSizeThreshold, the threshold is to account for filesystem overhead
  // variations.
  EXPECT_LT(result_usage, kFileSizeThreshold);

  // Since we are dealing with sparse files here, the apparent size should be
  // much much larger than the actual disk usage.
  EXPECT_LT(result_usage, result_size / 1000);
}

TEST_F(FileUtilsTest, ComputeDirectoryDiskUsageSymlinkFile) {
  // 2MB test file.
  constexpr size_t kFileSize = 2 * 1024 * 1024;

  const base::FilePath dirname(GetTempName());
  EXPECT_TRUE(base::CreateDirectory(dirname));
  const base::FilePath filename = dirname.Append("test.temp");
  const base::FilePath linkname = dirname.Append("test.link");

  std::string file_content = base::RandBytesAsString(kFileSize);
  EXPECT_TRUE(WriteStringToFile(filename, file_content));

  // Create a symlink.
  EXPECT_TRUE(base::CreateSymbolicLink(filename, linkname));

  int64_t result_usage = ComputeDirectoryDiskUsage(dirname);

  // result_usage (what we are testing here) should be within +/-10% of ground
  // truth. The variation is to account for filesystem overhead variations.
  // Note that it's not 2x kFileSize because symblink is not counted twice.
  EXPECT_GT(result_usage, kFileSize / 10 * 9);
  EXPECT_LT(result_usage, kFileSize / 10 * 11);
}

TEST_F(FileUtilsTest, ComputeDirectoryDiskUsageSymlinkDir) {
  // 2MB test file.
  constexpr size_t kFileSize = 2 * 1024 * 1024;

  const base::FilePath parentname(GetTempName());
  EXPECT_TRUE(base::CreateDirectory(parentname));
  const base::FilePath dirname = parentname.Append("target.dir");
  EXPECT_TRUE(base::CreateDirectory(dirname));
  const base::FilePath linkname = parentname.Append("link.dir");

  const base::FilePath filename = dirname.Append("test.temp");

  std::string file_content = base::RandBytesAsString(kFileSize);
  EXPECT_TRUE(WriteStringToFile(filename, file_content));

  // Create a symlink.
  EXPECT_TRUE(base::CreateSymbolicLink(dirname, linkname));

  int64_t result_usage = ComputeDirectoryDiskUsage(dirname);

  // result_usage (what we are testing here) should be within +/-10% of ground
  // truth. The variation is to account for filesystem overhead variations.
  // Note that it's not 2x kFileSize because symblink is not counted twice.
  EXPECT_GT(result_usage, kFileSize / 10 * 9);
  EXPECT_LT(result_usage, kFileSize / 10 * 11);
}

}  // namespace brillo
