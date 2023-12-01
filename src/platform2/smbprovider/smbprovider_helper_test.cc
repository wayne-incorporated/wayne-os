// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>
#include <vector>

#include <gtest/gtest.h>
#include <libsmbclient.h>

#include "smbprovider/constants.h"
#include "smbprovider/proto.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"
#include "smbprovider/smbprovider_helper.h"
#include "smbprovider/smbprovider_test_helper.h"
#include "smbprovider/temp_file_manager.h"

namespace smbprovider {

class SmbProviderHelperTest : public testing::Test {
 public:
  SmbProviderHelperTest() = default;
  SmbProviderHelperTest(const SmbProviderHelperTest&) = delete;
  SmbProviderHelperTest& operator=(const SmbProviderHelperTest&) = delete;

 protected:
  TempFileManager temp_file_manager_;
};

// Tests that AppendPath properly appends with or without the trailing separator
// "/" on the base path.
TEST_F(SmbProviderHelperTest, AppendPath) {
  EXPECT_EQ("smb://qnap/testshare/test",
            AppendPath("smb://qnap/testshare", "/test"));
  EXPECT_EQ("smb://qnap/testshare/test",
            AppendPath("smb://qnap/testshare/", "/test"));
  EXPECT_EQ("smb://qnap/testshare/test",
            AppendPath("smb://qnap/testshare", "test"));
  EXPECT_EQ("smb://qnap/testshare/test",
            AppendPath("smb://qnap/testshare/", "test"));
  EXPECT_EQ("smb://qnap/testshare", AppendPath("smb://qnap/testshare/", "/"));
  EXPECT_EQ("smb://qnap/testshare", AppendPath("smb://qnap/testshare/", ""));
}

// Should return true on "." and ".." entries.
TEST_F(SmbProviderHelperTest, IsSelfOrParentDir) {
  EXPECT_TRUE(IsSelfOrParentDir("."));
  EXPECT_TRUE(IsSelfOrParentDir(".."));
  EXPECT_FALSE(IsSelfOrParentDir("/"));
  EXPECT_FALSE(IsSelfOrParentDir("test.jpg"));
}

// Only SMBC_DIR and SMBC_FILE should return true.
TEST_F(SmbProviderHelperTest, IsFileOrDir) {
  EXPECT_TRUE(IsFileOrDir(SMBC_DIR));
  EXPECT_TRUE(IsFileOrDir(SMBC_FILE));

  EXPECT_FALSE(IsFileOrDir(SMBC_WORKGROUP));
  EXPECT_FALSE(IsFileOrDir(SMBC_SERVER));
  EXPECT_FALSE(IsFileOrDir(SMBC_FILE_SHARE));
  EXPECT_FALSE(IsFileOrDir(SMBC_PRINTER_SHARE));
  EXPECT_FALSE(IsFileOrDir(SMBC_COMMS_SHARE));
  EXPECT_FALSE(IsFileOrDir(SMBC_IPC_SHARE));
  EXPECT_FALSE(IsFileOrDir(SMBC_LINK));
}

// Only SMBC_FILE_SHARE should return true.
TEST_F(SmbProviderHelperTest, IsSmbShare) {
  EXPECT_TRUE(IsSmbShare(SMBC_FILE_SHARE));

  EXPECT_FALSE(IsSmbShare(SMBC_DIR));
  EXPECT_FALSE(IsSmbShare(SMBC_FILE));
  EXPECT_FALSE(IsSmbShare(SMBC_WORKGROUP));
  EXPECT_FALSE(IsSmbShare(SMBC_SERVER));
  EXPECT_FALSE(IsSmbShare(SMBC_PRINTER_SHARE));
  EXPECT_FALSE(IsSmbShare(SMBC_COMMS_SHARE));
  EXPECT_FALSE(IsSmbShare(SMBC_IPC_SHARE));
  EXPECT_FALSE(IsSmbShare(SMBC_LINK));
}

// Errors should be returned correctly.
TEST_F(SmbProviderHelperTest, GetErrorFromErrno) {
  EXPECT_EQ(ERROR_ACCESS_DENIED, GetErrorFromErrno(EPERM));
  EXPECT_EQ(ERROR_ACCESS_DENIED, GetErrorFromErrno(EACCES));

  EXPECT_EQ(ERROR_NOT_FOUND, GetErrorFromErrno(ENOENT));

  EXPECT_EQ(ERROR_TOO_MANY_OPENED, GetErrorFromErrno(EMFILE));
  EXPECT_EQ(ERROR_TOO_MANY_OPENED, GetErrorFromErrno(ENFILE));

  EXPECT_EQ(ERROR_NOT_A_DIRECTORY, GetErrorFromErrno(ENOTDIR));

  EXPECT_EQ(ERROR_NOT_A_FILE, GetErrorFromErrno(EISDIR));

  EXPECT_EQ(ERROR_NOT_EMPTY, GetErrorFromErrno(ENOTEMPTY));

  EXPECT_EQ(ERROR_EXISTS, GetErrorFromErrno(EEXIST));

  EXPECT_EQ(ERROR_INVALID_OPERATION, GetErrorFromErrno(EINVAL));

  EXPECT_EQ(ERROR_SMB1_UNSUPPORTED, GetErrorFromErrno(ECONNABORTED));

  EXPECT_EQ(ERROR_OPERATION_FAILED, GetErrorFromErrno(EBADF));
  EXPECT_EQ(ERROR_OPERATION_FAILED, GetErrorFromErrno(ENODEV));
  EXPECT_EQ(ERROR_OPERATION_FAILED, GetErrorFromErrno(ETIMEDOUT));

  // Errors without an explicit mapping get mapped
  // to ERROR_FAILED.
  EXPECT_EQ(ERROR_FAILED, GetErrorFromErrno(ENOSPC));
  EXPECT_EQ(ERROR_FAILED, GetErrorFromErrno(ESPIPE));
}

// Errors should be returned correctly.
TEST_F(SmbProviderHelperTest, GetErrorFromErrnoForReadDir) {
  EXPECT_EQ(ERROR_ACCESS_DENIED, GetErrorFromErrnoForReadDir(EPERM));
  EXPECT_EQ(ERROR_ACCESS_DENIED, GetErrorFromErrnoForReadDir(EACCES));

  EXPECT_EQ(ERROR_NOT_FOUND, GetErrorFromErrnoForReadDir(ENOENT));
  // EINVAL is returned when Samba attempts to parse a hostname
  // (eg. \\qnap\testshare).
  EXPECT_EQ(ERROR_NOT_FOUND, GetErrorFromErrnoForReadDir(EINVAL));

  EXPECT_EQ(ERROR_TOO_MANY_OPENED, GetErrorFromErrnoForReadDir(EMFILE));
  EXPECT_EQ(ERROR_TOO_MANY_OPENED, GetErrorFromErrnoForReadDir(ENFILE));

  EXPECT_EQ(ERROR_NOT_A_DIRECTORY, GetErrorFromErrnoForReadDir(ENOTDIR));

  EXPECT_EQ(ERROR_NOT_A_FILE, GetErrorFromErrnoForReadDir(EISDIR));

  EXPECT_EQ(ERROR_NOT_EMPTY, GetErrorFromErrnoForReadDir(ENOTEMPTY));

  EXPECT_EQ(ERROR_EXISTS, GetErrorFromErrnoForReadDir(EEXIST));

  EXPECT_EQ(ERROR_SMB1_UNSUPPORTED, GetErrorFromErrnoForReadDir(ECONNABORTED));

  EXPECT_EQ(ERROR_OPERATION_FAILED, GetErrorFromErrno(EBADF));
  EXPECT_EQ(ERROR_OPERATION_FAILED, GetErrorFromErrno(ENODEV));
  EXPECT_EQ(ERROR_OPERATION_FAILED, GetErrorFromErrno(ETIMEDOUT));

  // Errors without an explicit mapping get mapped
  // to ERROR_FAILED.
  EXPECT_EQ(ERROR_FAILED, GetErrorFromErrnoForReadDir(ENOSPC));
  EXPECT_EQ(ERROR_FAILED, GetErrorFromErrnoForReadDir(ESPIPE));
}

// IsDirectory should only return true on directory stats.
TEST_F(SmbProviderHelperTest, IsDirectory) {
  struct stat dir_info;
  dir_info.st_mode = 16877;  // Dir mode
  struct stat file_info;
  file_info.st_mode = 33188;  // File mode

  EXPECT_TRUE(IsDirectory(dir_info));
  EXPECT_FALSE(IsDirectory(file_info));
}

// IsFile should only return true on File stats.
TEST_F(SmbProviderHelperTest, IsFile) {
  struct stat dir_info;
  dir_info.st_mode = 16877;  // Dir mode
  struct stat file_info;
  file_info.st_mode = 33188;  // File mode

  EXPECT_TRUE(IsFile(file_info));
  EXPECT_FALSE(IsFile(dir_info));
}

// IsValidOpenFileFlags should return true on valid flags.
TEST_F(SmbProviderHelperTest, IsValidOpenFileFlags) {
  EXPECT_TRUE(IsValidOpenFileFlags(O_RDWR));
  EXPECT_TRUE(IsValidOpenFileFlags(O_RDONLY));
  EXPECT_TRUE(IsValidOpenFileFlags(O_WRONLY));
  EXPECT_FALSE(IsValidOpenFileFlags(O_CREAT));
  EXPECT_FALSE(IsValidOpenFileFlags(O_TRUNC));
}

// SplitPath correctly splits a relative path into a vector of its components.
TEST_F(SmbProviderHelperTest, SplitPathCorrectlySplitsPath) {
  const std::string relative_path = "/testShare/dogs/lab.jpg";

  PathParts parts = SplitPath(relative_path);

  EXPECT_EQ(4, parts.size());
  EXPECT_EQ("/", parts[0]);
  EXPECT_EQ("testShare", parts[1]);
  EXPECT_EQ("dogs", parts[2]);
  EXPECT_EQ("lab.jpg", parts[3]);
}

// SplitPath correctly splits a standalone leading slash and a standalone
// directory.
TEST_F(SmbProviderHelperTest, SplitPathCorrectlySplitsRoot) {
  const std::string root_path = "/";

  PathParts parts = SplitPath(root_path);

  EXPECT_EQ(1, parts.size());
  EXPECT_EQ("/", parts[0]);
}

// SplitPath correctly splits a standalone directory.
TEST_F(SmbProviderHelperTest, SplitPathCorrectlySplitsDirPath) {
  const std::string dir_path = "/foo";

  PathParts parts = SplitPath(dir_path);

  EXPECT_EQ(2, parts.size());
  EXPECT_EQ("/", parts[0]);
  EXPECT_EQ("foo", parts[1]);
}

// RemoveUrlScheme correctly removes the SMB Url scheme from an SMB Url.
TEST_F(SmbProviderHelperTest, RemoveUrlSchemeCorrectlyRemovesUrl) {
  EXPECT_EQ("/testShare/dogs", RemoveURLScheme("smb://testShare/dogs"));
}

// GetFileName correctly returns root when passed "smb://".
TEST_F(SmbProviderHelperTest, GetFileNameReturnsRoot) {
  const std::string full_path = "smb://";

  EXPECT_EQ("/", GetFileName(full_path));
}

// GetFileName correctly returns the filename when passed "smb://foo".
TEST_F(SmbProviderHelperTest, GetFileNameReturnsFileNameOnSingleDepth) {
  const std::string full_path = "smb://foo";

  EXPECT_EQ("foo", GetFileName(full_path));
}

// GetFileName correctly returns the filename from an SMB Url.
TEST_F(SmbProviderHelperTest, GetFileNameReturnsFileName) {
  const std::string full_path = "smb://testShare/dogs/lab.jpg";

  EXPECT_EQ("lab.jpg", GetFileName(full_path));
}

// GetDirPath correctly returns root when passed "smb://".
TEST_F(SmbProviderHelperTest, GetDirPathReturnsRoot) {
  const std::string full_path = "smb://";

  EXPECT_EQ("/", GetDirPath(full_path));
}

// GetDirPath correctly returns the dirpath when passed "smb://foo".
TEST_F(SmbProviderHelperTest, GetDirPathReturnsRootOnSingleDepth) {
  const std::string full_path = "smb://foo";

  EXPECT_EQ("/", GetDirPath(full_path));
}

// GetDirPath correctly returns the dirpath from an SMB Url.
TEST_F(SmbProviderHelperTest, GetDirPathReturnsParent) {
  const std::string full_path = "smb://testShare/dogs/lab.jpg";

  EXPECT_EQ("/testShare/dogs", GetDirPath(full_path));
}

TEST_F(SmbProviderHelperTest, ShouldReportCreateDirError) {
  EXPECT_FALSE(
      ShouldReportCreateDirError(0 /* result */, false /* ignore_existing */));
  EXPECT_FALSE(
      ShouldReportCreateDirError(0 /* result */, true /* ignore_existing */));
  EXPECT_FALSE(ShouldReportCreateDirError(EEXIST, true /* ignore_existing */));
  EXPECT_TRUE(ShouldReportCreateDirError(EEXIST, false /* ignore_existing */));
  EXPECT_TRUE(ShouldReportCreateDirError(EPERM, false /* ignore_existing */));
  EXPECT_TRUE(ShouldReportCreateDirError(EPERM, true /* ignore_existing */));
}

TEST_F(SmbProviderHelperTest, GetOpenFilePermissionsBoolean) {
  EXPECT_EQ(O_RDWR, GetOpenFilePermissions(true));

  EXPECT_EQ(O_RDONLY, GetOpenFilePermissions(false));
}

namespace {

std::string ToString(ErrorType error) {
  std::ostringstream out;
  out << error;
  return out.str();
}

}  // namespace

TEST_F(SmbProviderHelperTest, ErrorTypeOutputOperator) {
  EXPECT_EQ(ToString(ERROR_NONE), "ERROR_NONE");
  EXPECT_EQ(ToString(ERROR_OK), "ERROR_OK");
  EXPECT_EQ(ToString(ERROR_FAILED), "ERROR_FAILED");
  EXPECT_EQ(ToString(ERROR_IN_USE), "ERROR_IN_USE");
  EXPECT_EQ(ToString(ERROR_EXISTS), "ERROR_EXISTS");
  EXPECT_EQ(ToString(ERROR_NOT_FOUND), "ERROR_NOT_FOUND");
  EXPECT_EQ(ToString(ERROR_ACCESS_DENIED), "ERROR_ACCESS_DENIED");
  EXPECT_EQ(ToString(ERROR_TOO_MANY_OPENED), "ERROR_TOO_MANY_OPENED");
  EXPECT_EQ(ToString(ERROR_NO_MEMORY), "ERROR_NO_MEMORY");
  EXPECT_EQ(ToString(ERROR_NO_SPACE), "ERROR_NO_SPACE");
  EXPECT_EQ(ToString(ERROR_NOT_A_DIRECTORY), "ERROR_NOT_A_DIRECTORY");
  EXPECT_EQ(ToString(ERROR_INVALID_OPERATION), "ERROR_INVALID_OPERATION");
  EXPECT_EQ(ToString(ERROR_SECURITY), "ERROR_SECURITY");
  EXPECT_EQ(ToString(ERROR_ABORT), "ERROR_ABORT");
  EXPECT_EQ(ToString(ERROR_NOT_A_FILE), "ERROR_NOT_A_FILE");
  EXPECT_EQ(ToString(ERROR_NOT_EMPTY), "ERROR_NOT_EMPTY");
  EXPECT_EQ(ToString(ERROR_INVALID_URL), "ERROR_INVALID_URL");
  EXPECT_EQ(ToString(ERROR_IO), "ERROR_IO");
  EXPECT_EQ(ToString(ERROR_PROVIDER_ERROR_COUNT), "ERROR_PROVIDER_ERROR_COUNT");
  EXPECT_EQ(ToString(ERROR_DBUS_PARSE_FAILED), "ERROR_DBUS_PARSE_FAILED");
  EXPECT_EQ(ToString(ERROR_COPY_PENDING), "ERROR_COPY_PENDING");
  EXPECT_EQ(ToString(ERROR_COPY_FAILED), "ERROR_COPY_FAILED");
  EXPECT_EQ(ToString(ERROR_SMB1_UNSUPPORTED), "ERROR_SMB1_UNSUPPORTED");
  EXPECT_EQ(ToString(ERROR_OPERATION_PENDING), "ERROR_OPERATION_PENDING");
  EXPECT_EQ(ToString(ERROR_OPERATION_FAILED), "ERROR_OPERATION_FAILED");
  EXPECT_EQ(ToString(ErrorType(987654)), "ERROR_987654");
}

}  // namespace smbprovider
