// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/files/file_util_test.h"

#include <iterator>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/files/file_util.h>
#include <brillo/files/safe_fd.h>

namespace brillo {

namespace {

base::ScopedClosureRunner SetCurrentDirectoryScoped(base::FilePath change_to) {
  base::FilePath current;
  CHECK(base::GetCurrentDirectory(&current));

  auto scoped_callback = base::ScopedClosureRunner(base::BindOnce(
      [](const base::FilePath& current) {
        ASSERT_TRUE(base::SetCurrentDirectory(current));
      },
      current));

  CHECK(base::SetCurrentDirectory(change_to));
  return scoped_callback;
}

}  // namespace

#define TO_STRING_HELPER(x)      \
  case brillo::SafeFD::Error::x: \
    return #x;
std::string to_string(brillo::SafeFD::Error err) {
  switch (err) {
    TO_STRING_HELPER(kNoError)
    TO_STRING_HELPER(kBadArgument)
    TO_STRING_HELPER(kNotInitialized)
    TO_STRING_HELPER(kIOError)
    TO_STRING_HELPER(kDoesNotExist)
    TO_STRING_HELPER(kSymlinkDetected)
    TO_STRING_HELPER(kWrongType)
    TO_STRING_HELPER(kWrongUID)
    TO_STRING_HELPER(kWrongGID)
    TO_STRING_HELPER(kWrongPermissions)
    TO_STRING_HELPER(kExceededMaximum)
    default:
      return std::string("unknown (") + std::to_string(static_cast<int>(err)) +
             ")";
  }
}
#undef TO_STRING_HELPER

std::ostream& operator<<(std::ostream& os, const brillo::SafeFD::Error err) {
  return os << to_string(err);  // whatever needed to print bar to os
}

std::string GetRandomSuffix() {
  const int kBufferSize = 6;
  unsigned char buffer[kBufferSize];
  base::RandBytes(buffer, std::size(buffer));
  return base::HexEncode(buffer, std::size(buffer));
}

void FileTest::SetUpTestCase() {
  umask(0);
}

FileTest::FileTest() {
  CHECK(temp_dir_.CreateUniqueTempDir()) << strerror(errno);
  sub_dir_path_ = temp_dir_.GetPath().Append(kSubdirName);
  file_path_ = sub_dir_path_.Append(kFileName);

  std::string path = temp_dir_.GetPath().value();
  temp_dir_path_.reserve(path.size() + 1);
  temp_dir_path_.assign(temp_dir_.GetPath().value().begin(),
                        temp_dir_.GetPath().value().end());
  temp_dir_path_.push_back('\0');

  CHECK_EQ(chmod(temp_dir_path_.data(), SafeFD::kDefaultDirPermissions), 0);
  SafeFD::SetRootPathForTesting(temp_dir_path_.data());
  root_ = SafeFD::Root().first;
  CHECK(root_.is_valid());
}

FileTest::~FileTest() {
  // Restore root path to avoid UaF.
  SafeFD::SetRootPathForTesting("/");
}

bool FileTest::SetupSubdir() {
  if (!base::CreateDirectory(sub_dir_path_)) {
    PLOG(ERROR) << "Failed to create '" << sub_dir_path_.value() << "'";
    return false;
  }
  if (chmod(sub_dir_path_.value().c_str(), SafeFD::kDefaultDirPermissions) !=
      0) {
    PLOG(ERROR) << "Failed to set permissions of '" << sub_dir_path_.value()
                << "'";
    return false;
  }
  return true;
}

bool FileTest::SetupSymlinks() {
  symlink_file_path_ = temp_dir_.GetPath().Append(kSymbolicFileName);
  symlink_dir_path_ = temp_dir_.GetPath().Append(kSymbolicDirName);
  if (!base::CreateSymbolicLink(file_path_, symlink_file_path_)) {
    PLOG(ERROR) << "Failed to create symlink to '" << symlink_file_path_.value()
                << "'";
    return false;
  }
  if (!base::CreateSymbolicLink(temp_dir_.GetPath(), symlink_dir_path_)) {
    PLOG(ERROR) << "Failed to create symlink to'" << symlink_dir_path_.value()
                << "'";
    return false;
  }
  return true;
}

bool FileTest::WriteFile(const std::string& contents) {
  if (!SetupSubdir()) {
    return false;
  }
  if (contents.length() !=
      base::WriteFile(file_path_, contents.c_str(), contents.length())) {
    PLOG(ERROR) << "base::WriteFile failed";
    return false;
  }
  if (chmod(file_path_.value().c_str(), SafeFD::kDefaultFilePermissions) != 0) {
    PLOG(ERROR) << "chmod failed";
    return false;
  }
  return true;
}

void FileTest::ExpectFileContains(const std::string& contents) {
  EXPECT_TRUE(base::PathExists(file_path_));
  std::string new_contents;
  EXPECT_TRUE(base::ReadFileToString(file_path_, &new_contents));
  EXPECT_EQ(contents, new_contents);
}

void FileTest::ExpectPermissions(base::FilePath path, int permissions) {
  int actual_permissions = 0;
  // This breaks out of the ExpectPermissions() call but not the test case.
  ASSERT_TRUE(base::GetPosixFilePermissions(path, &actual_permissions));
  EXPECT_EQ(permissions, actual_permissions);
}

// Creates a file with a random name in the temporary directory.
base::FilePath FileTest::GetTempName() {
  return temp_dir_.GetPath().Append(GetRandomSuffix());
}

constexpr char FileTest::kFileName[];
constexpr char FileTest::kSubdirName[];
constexpr char FileTest::kSymbolicFileName[];
constexpr char FileTest::kSymbolicDirName[];

class FileUtilTest : public FileTest {};

TEST_F(FileUtilTest, GetFDPath_SimpleSuccess) {
  EXPECT_EQ(GetFDPath(root_.get()), temp_dir_.GetPath());
}

TEST_F(FileUtilTest, GetFDPath_BadFD) {
  base::FilePath path = GetFDPath(-1);
  EXPECT_TRUE(path.empty());
}

TEST_F(FileUtilTest, OpenOrRemakeDir_SimpleSuccess) {
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(temp_dir_.GetPath());
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());

  SafeFD subdir;
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, kSubdirName);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  EXPECT_TRUE(subdir.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeDir_SuccessAfterRetry) {
  ASSERT_NE(base::WriteFile(sub_dir_path_, "", 0), -1);
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(temp_dir_.GetPath());
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());

  SafeFD subdir;
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, kSubdirName);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  EXPECT_TRUE(subdir.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeDir_BadArgument) {
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(temp_dir_.GetPath());
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());

  SafeFD subdir;
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, ".");
  EXPECT_EQ(err, SafeFD::Error::kBadArgument);
  EXPECT_FALSE(subdir.is_valid());
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, "..");
  EXPECT_EQ(err, SafeFD::Error::kBadArgument);
  EXPECT_FALSE(subdir.is_valid());
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, "a/a");
  EXPECT_EQ(err, SafeFD::Error::kBadArgument);
  EXPECT_FALSE(subdir.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeDir_NotInitialized) {
  SafeFD::Error err;
  SafeFD dir;

  SafeFD subdir;
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, kSubdirName);
  EXPECT_EQ(err, SafeFD::Error::kNotInitialized);
  EXPECT_FALSE(subdir.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeDir_IOError) {
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(temp_dir_.GetPath());
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());
  ASSERT_EQ(chmod(temp_dir_path_.data(), 0000), 0);

  SafeFD subdir;
  std::tie(subdir, err) = OpenOrRemakeDir(&dir, kSubdirName);
  EXPECT_EQ(err, SafeFD::Error::kIOError);
  EXPECT_FALSE(subdir.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeFile_SimpleSuccess) {
  ASSERT_TRUE(SetupSubdir());
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(sub_dir_path_);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());

  SafeFD file;
  std::tie(file, err) = OpenOrRemakeFile(&dir, kFileName);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  EXPECT_TRUE(file.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeFile_SuccessAfterRetry) {
  ASSERT_TRUE(SetupSubdir());
  ASSERT_TRUE(base::CreateDirectory(file_path_));
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(sub_dir_path_);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());

  SafeFD file;
  std::tie(file, err) = OpenOrRemakeFile(&dir, kFileName);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  EXPECT_TRUE(file.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeFile_NotInitialized) {
  ASSERT_TRUE(SetupSubdir());
  SafeFD::Error err;
  SafeFD dir;

  SafeFD file;
  std::tie(file, err) = OpenOrRemakeFile(&dir, kFileName);
  EXPECT_EQ(err, SafeFD::Error::kNotInitialized);
  EXPECT_FALSE(file.is_valid());
}

TEST_F(FileUtilTest, OpenOrRemakeFile_IOError) {
  ASSERT_TRUE(SetupSubdir());
  SafeFD::Error err;
  SafeFD dir;

  std::tie(dir, err) = root_.OpenExistingDir(sub_dir_path_);
  EXPECT_EQ(err, SafeFD::Error::kNoError);
  ASSERT_TRUE(dir.is_valid());
  ASSERT_EQ(chmod(sub_dir_path_.value().c_str(), 0000), 0);

  SafeFD file;
  std::tie(file, err) = OpenOrRemakeFile(&dir, kFileName);
  EXPECT_EQ(err, SafeFD::Error::kIOError);
  EXPECT_FALSE(file.is_valid());
}

TEST_F(FileUtilTest, SimplifyPath_Success) {
  EXPECT_EQ(SimplifyPath(base::FilePath("/")).value(), "/");
  EXPECT_EQ(SimplifyPath(base::FilePath("/..")).value(), "/");
  EXPECT_EQ(SimplifyPath(base::FilePath("/../..")).value(), "/");
  EXPECT_EQ(SimplifyPath(base::FilePath("/a/..")).value(), "/");
  EXPECT_EQ(SimplifyPath(base::FilePath("/../a")).value(), "/a");
  EXPECT_EQ(SimplifyPath(base::FilePath("/a/b/c////.././d/../..")).value(),
            "/a");

  EXPECT_EQ(SimplifyPath(base::FilePath("a")).value(), "a");
  EXPECT_EQ(SimplifyPath(base::FilePath("a/b/c/d")).value(), "a/b/c/d");
  EXPECT_EQ(SimplifyPath(base::FilePath("a////b/c/.//./d//")).value(),
            "a/b/c/d");
  EXPECT_EQ(SimplifyPath(base::FilePath("../../a/b/c/../d/../..")).value(),
            "../../a");
}

TEST_F(FileUtilTest, DeleteFileRelative_Success) {
  ASSERT_TRUE(SetupSubdir());

  auto scoped_callback =
      SetCurrentDirectoryScoped(base::FilePath(temp_dir_path_.data()));

  ASSERT_TRUE(WriteFile(""));

  EXPECT_TRUE(brillo::DeleteFile(base::FilePath(kSubdirName)
                                     .Append("..")
                                     .Append(kSubdirName)
                                     .Append(kFileName)));
  EXPECT_FALSE(base::PathExists(file_path_));

  // Check for success when the path does not exist.
  EXPECT_TRUE(brillo::DeleteFile(
      base::FilePath(std::string(kSubdirName) + "/" + kFileName)));
}

TEST_F(FileUtilTest, DeletePathRecursivelyRelative_Success) {
  ASSERT_TRUE(SetupSubdir());

  auto scoped_callback =
      SetCurrentDirectoryScoped(base::FilePath(temp_dir_path_.data()));

  ASSERT_TRUE(WriteFile(""));

  EXPECT_TRUE(brillo::DeletePathRecursively(
      base::FilePath(kSubdirName).Append("..").Append(kSubdirName)));
  EXPECT_FALSE(base::PathExists(sub_dir_path_));

  // Check for success when the path does not exist.
  EXPECT_TRUE(brillo::DeletePathRecursively(base::FilePath(kSubdirName)));
}

}  // namespace brillo
