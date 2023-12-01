// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/files/file_util.h>
#include <gtest/gtest.h>

#include "init/startup/fake_platform_impl.h"
#include "init/startup/mock_platform_impl.h"
#include "init/startup/platform_impl.h"
#include "init/startup/security_manager.h"

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::InvokeWithoutArgs;
using testing::Return;
using testing::StrictMock;

namespace {

// Define in test to catch source changes in flags.
constexpr auto kWriteFlags = O_WRONLY | O_NOFOLLOW | O_CLOEXEC;
constexpr auto kReadFlags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;

constexpr char kStatefulPartition[] = "mnt/stateful_partition";
constexpr char kSysKeyLog[] = "run/create_system_key.log";
constexpr char kPreserveSysKeyFile[] = "unencrypted/preserve/system.key";

MATCHER_P(IntPtrCheck, expected, "") {
  return *arg == expected;
}

// Helper function to create directory and write to file.
bool CreateDirAndWriteFile(const base::FilePath& path,
                           const std::string& contents) {
  return base::CreateDirectory(path.DirName()) &&
         base::WriteFile(path, contents.c_str(), contents.length()) ==
             contents.length();
}

bool ExceptionsTestFunc(const base::FilePath& root, const std::string& path) {
  base::FilePath allow = root.Append("allow_file");
  base::AppendToFile(allow, path);
  return base::AppendToFile(allow, "\n");
}

}  // namespace

class SecurityManagerTest : public ::testing::Test {
 protected:
  SecurityManagerTest() {}

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir_ = temp_dir_.GetPath();
    mock_platform_ = std::make_unique<StrictMock<startup::MockPlatform>>();
  }

  std::unique_ptr<startup::MockPlatform> mock_platform_;

  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir_;
};

class SecurityManagerLoadPinTest : public SecurityManagerTest {
 protected:
  SecurityManagerLoadPinTest() {}

  void SetUp() override {
    SecurityManagerTest::SetUp();

    loadpin_verity_path_ =
        base_dir_.Append("sys/kernel/security/loadpin/dm-verity");
    CreateDirAndWriteFile(loadpin_verity_path_, kNull);

    trusted_verity_digests_path_ =
        base_dir_.Append("opt/google/dlc/_trusted_verity_digests");
    CreateDirAndWriteFile(trusted_verity_digests_path_, kRootDigest);

    dev_null_path_ = base_dir_.Append("dev/null");
    CreateDirAndWriteFile(dev_null_path_, kNull);
  }

  base::FilePath loadpin_verity_path_;
  base::FilePath trusted_verity_digests_path_;
  base::FilePath dev_null_path_;
  const std::string kRootDigest =
      "fb066d299c657b127ecc2c11f841cabf14c717eb6f03630ef788e6e1cca17f52";
  const std::string kNull = "\0";
};

TEST_F(SecurityManagerTest, Before_v4_4) {
  base::FilePath policies_dir =
      base_dir_.Append("usr/share/cros/startup/process_management_policies");
  base::FilePath mgmt_policies = base_dir_.Append(
      "sys/kernel/security/chromiumos/process_management_policies/"
      "add_whitelist_policy");
  ASSERT_TRUE(CreateDirAndWriteFile(mgmt_policies, ""));
  base::FilePath safesetid_mgmt_policies =
      base_dir_.Append("sys/kernel/security/safesetid/whitelist_policy");
  ASSERT_TRUE(CreateDirAndWriteFile(safesetid_mgmt_policies, "#AllowList"));
  base::FilePath allow_1 = policies_dir.Append("allow_1.txt");
  ASSERT_TRUE(CreateDirAndWriteFile(allow_1, "254:607\n607:607"));

  startup::ConfigureProcessMgmtSecurity(base_dir_);

  std::string allow;
  base::ReadFileToString(mgmt_policies, &allow);
  EXPECT_EQ(allow, "254:607\n607:607\n");
}

TEST_F(SecurityManagerTest, After_v4_14) {
  base::FilePath policies_dir =
      base_dir_.Append("usr/share/cros/startup/process_management_policies");
  base::FilePath mgmt_policies =
      base_dir_.Append("sys/kernel/security/safesetid/whitelist_policy");
  ASSERT_TRUE(CreateDirAndWriteFile(mgmt_policies, "#AllowList"));
  base::FilePath allow_1 = policies_dir.Append("allow_1.txt");
  std::string result1 = "254:607\n607:607";
  std::string full1 = "254:607\n607:607\n#Comment\n\n#Ignore";
  ASSERT_TRUE(CreateDirAndWriteFile(allow_1, full1));
  base::FilePath allow_2 = policies_dir.Append("allow_2.txt");
  std::string result2 = "20104:224\n20104:217\n217:217";
  std::string full2 = "#Comment\n\n20104:224\n20104:217\n#Ignore\n217:217";
  ASSERT_TRUE(CreateDirAndWriteFile(allow_2, full2));

  startup::ConfigureProcessMgmtSecurity(base_dir_);

  std::string allow;
  base::ReadFileToString(mgmt_policies, &allow);

  EXPECT_NE(allow.find(result1), std::string::npos);
  EXPECT_NE(allow.find(result2), std::string::npos);

  std::vector<std::string> allow_vec = base::SplitString(
      allow, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  std::vector<std::string> expected = {"254:607", "607:607", "20104:224",
                                       "20104:217", "217:217"};
  sort(allow_vec.begin(), allow_vec.end());
  sort(expected.begin(), expected.end());
  EXPECT_EQ(allow_vec, expected);
}

TEST_F(SecurityManagerTest, After_v5_9) {
  base::FilePath policies_dir =
      base_dir_.Append("usr/share/cros/startup/process_management_policies");
  base::FilePath mgmt_policies =
      base_dir_.Append("sys/kernel/security/safesetid/uid_allowlist_policy");
  ASSERT_TRUE(CreateDirAndWriteFile(mgmt_policies, "#AllowList"));
  base::FilePath allow_1 = policies_dir.Append("allow_1.txt");
  std::string result1 = "254:607\n607:607";
  ASSERT_TRUE(CreateDirAndWriteFile(allow_1, result1));
  base::FilePath allow_2 = policies_dir.Append("allow_2.txt");
  std::string result2 = "20104:224\n20104:217\n217:217";
  ASSERT_TRUE(CreateDirAndWriteFile(allow_2, result2));

  startup::ConfigureProcessMgmtSecurity(base_dir_);

  std::string allow;
  base::ReadFileToString(mgmt_policies, &allow);

  EXPECT_NE(allow.find(result1), std::string::npos);
  EXPECT_NE(allow.find(result2), std::string::npos);
}

TEST_F(SecurityManagerTest, EmptyAfter_v5_9) {
  base::FilePath mgmt_policies =
      base_dir_.Append("sys/kernel/security/safesetid/uid_allowlist_policy");
  ASSERT_TRUE(CreateDirAndWriteFile(mgmt_policies, "#AllowList"));

  EXPECT_EQ(startup::ConfigureProcessMgmtSecurity(base_dir_), false);

  std::string allow;
  base::ReadFileToString(mgmt_policies, &allow);

  EXPECT_EQ(allow, "#AllowList");
}

TEST_F(SecurityManagerLoadPinTest, LoadPinAttributeUnsupported) {
  ASSERT_TRUE(brillo::DeleteFile(loadpin_verity_path_));

  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(),
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  // int fd = loadpin_verity.get();
  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, _))
      .WillOnce(Return(ByMove(std::move(loadpin_verity))));
  // `loadpin_verity` is moved, do not use.
  EXPECT_CALL(*mock_platform_, Ioctl(_, _, _)).Times(0);

  EXPECT_TRUE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

TEST_F(SecurityManagerLoadPinTest, FailureToOpenLoadPinVerity) {
  ASSERT_TRUE(brillo::DeleteFile(loadpin_verity_path_));

  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(), kWriteFlags)));
  // int fd = loadpin_verity.get();
  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, kWriteFlags))
      .WillOnce(DoAll(
          // Override the `errno` to be non-`ENOENT`.
          InvokeWithoutArgs([] { errno = EACCES; }),
          Return(ByMove(std::move(loadpin_verity)))));
  // `loadpin_verity` is moved, do not use.
  EXPECT_CALL(*mock_platform_, Ioctl(_, _, _)).Times(0);

  // The call should fail as failure to open LoadPin verity file.
  EXPECT_FALSE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

TEST_F(SecurityManagerLoadPinTest, ValidDigests) {
  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(), kWriteFlags)));
  int fd = loadpin_verity.get();

  base::ScopedFD trusted_verity_digests(HANDLE_EINTR(
      open(trusted_verity_digests_path_.value().c_str(), kReadFlags)));
  int digests_fd = trusted_verity_digests.get();

  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, kWriteFlags))
      .WillOnce(Return(ByMove(std::move(loadpin_verity))));
  // `loadpin_verity` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(trusted_verity_digests_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(trusted_verity_digests))));
  // `trusted_verity_digests` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Ioctl(fd, _, IntPtrCheck(digests_fd)))
      .WillOnce(Return(0));

  EXPECT_TRUE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

TEST_F(SecurityManagerLoadPinTest, MissingDigests) {
  ASSERT_TRUE(brillo::DeleteFile(trusted_verity_digests_path_));

  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(), kWriteFlags)));
  int fd = loadpin_verity.get();

  base::ScopedFD trusted_verity_digests(HANDLE_EINTR(
      open(trusted_verity_digests_path_.value().c_str(), kReadFlags)));

  base::ScopedFD dev_null(
      HANDLE_EINTR(open(dev_null_path_.value().c_str(), kReadFlags)));
  int dev_null_fd = dev_null.get();

  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, kWriteFlags))
      .WillOnce(Return(ByMove(std::move(loadpin_verity))));
  // `loadpin_verity` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(trusted_verity_digests_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(trusted_verity_digests))));
  // `trusted_verity_digests` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(dev_null_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(dev_null))));
  // `dev_null` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Ioctl(fd, _, IntPtrCheck(dev_null_fd)))
      .WillOnce(Return(0));

  EXPECT_TRUE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

TEST_F(SecurityManagerLoadPinTest, FailureToReadDigests) {
  ASSERT_TRUE(brillo::DeleteFile(trusted_verity_digests_path_));

  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(), kWriteFlags)));
  int fd = loadpin_verity.get();

  base::ScopedFD trusted_verity_digests(HANDLE_EINTR(
      open(trusted_verity_digests_path_.value().c_str(), kReadFlags)));

  base::ScopedFD dev_null(
      HANDLE_EINTR(open(dev_null_path_.value().c_str(), kReadFlags)));
  int dev_null_fd = dev_null.get();

  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, kWriteFlags))
      .WillOnce(Return(ByMove(std::move(loadpin_verity))));
  // `loadpin_verity` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(trusted_verity_digests_path_, kReadFlags))
      .WillOnce(DoAll(
          // Override the `errno` to be non-`ENOENT`.
          InvokeWithoutArgs([] { errno = EACCES; }),
          Return(ByMove(std::move(trusted_verity_digests)))));
  // `trusted_verity_digests` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(dev_null_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(dev_null))));
  // `dev_null` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Ioctl(fd, _, IntPtrCheck(dev_null_fd)))
      .WillOnce(Return(0));

  EXPECT_TRUE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

TEST_F(SecurityManagerLoadPinTest, FailureToReadInvalidDigestsDevNull) {
  ASSERT_TRUE(brillo::DeleteFile(trusted_verity_digests_path_));
  ASSERT_TRUE(brillo::DeleteFile(dev_null_path_));

  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(), kWriteFlags)));

  base::ScopedFD trusted_verity_digests(HANDLE_EINTR(
      open(trusted_verity_digests_path_.value().c_str(), kReadFlags)));

  base::ScopedFD dev_null(
      HANDLE_EINTR(open(dev_null_path_.value().c_str(), kReadFlags)));

  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, kWriteFlags))
      .WillOnce(Return(ByMove(std::move(loadpin_verity))));
  // `loadpin_verity` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(trusted_verity_digests_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(trusted_verity_digests))));
  // `trusted_verity_digests` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(dev_null_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(dev_null))));
  // `dev_null` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Ioctl(_, _, _)).Times(0);

  EXPECT_FALSE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

TEST_F(SecurityManagerLoadPinTest, FailureToFeedLoadPin) {
  base::ScopedFD loadpin_verity(
      HANDLE_EINTR(open(loadpin_verity_path_.value().c_str(), kWriteFlags)));
  int fd = loadpin_verity.get();

  base::ScopedFD trusted_verity_digests(HANDLE_EINTR(
      open(trusted_verity_digests_path_.value().c_str(), kReadFlags)));
  int digests_fd = trusted_verity_digests.get();

  EXPECT_CALL(*mock_platform_, Open(loadpin_verity_path_, kWriteFlags))
      .WillOnce(Return(ByMove(std::move(loadpin_verity))));
  // `loadpin_verity` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Open(trusted_verity_digests_path_, kReadFlags))
      .WillOnce(Return(ByMove(std::move(trusted_verity_digests))));
  // `trusted_verity_digests` is moved, do not use.

  EXPECT_CALL(*mock_platform_, Ioctl(fd, _, IntPtrCheck(digests_fd)))
      .WillOnce(Return(-1));

  EXPECT_FALSE(
      startup::SetupLoadPinVerityDigests(base_dir_, mock_platform_.get()));
}

class SysKeyTest : public ::testing::Test {
 protected:
  SysKeyTest() {}

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir = temp_dir_.GetPath();
    stateful = base_dir.Append(kStatefulPartition);
    log_file = base_dir.Append(kSysKeyLog);
    platform_ = std::make_unique<startup::FakePlatform>();
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir;
  base::FilePath stateful;
  base::FilePath log_file;
  std::unique_ptr<startup::FakePlatform> platform_;
};

TEST_F(SysKeyTest, NoEarlySysKeyFile) {
  base::FilePath no_early = stateful.Append(".no_early_system_key");
  ASSERT_TRUE(CreateDirAndWriteFile(no_early, "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(log_file, "1"));

  struct stat st;
  st.st_mode = S_IFREG;
  platform_->SetStatResultForPath(no_early, st);
  startup::CreateSystemKey(base_dir, stateful, platform_.get());

  std::string res;
  base::ReadFileToString(log_file, &res);
  EXPECT_EQ(res, "Opt not to create a system key in advance.");
}

TEST_F(SysKeyTest, AlreadySysKey) {
  ASSERT_TRUE(CreateDirAndWriteFile(log_file, "1"));
  platform_->SetMountEncOutputForArg("info", "NVRAM: available.");

  startup::CreateSystemKey(base_dir, stateful, platform_.get());

  std::string res;
  base::ReadFileToString(log_file, &res);
  std::string expected =
      "Checking if a system key already exists in NVRAM...\n";
  expected.append("NVRAM: available.\n");
  expected.append("There is already a system key in NVRAM.\n");
  EXPECT_EQ(res, expected);
}

TEST_F(SysKeyTest, NeedSysKeyBadRandomWrite) {
  // base::FilePath backup = stateful.Append(kPreserveSysKeyFile);
  ASSERT_TRUE(CreateDirAndWriteFile(log_file, "1"));
  // ASSERT_TRUE(CreateDirAndWriteFile(backup, "1"));
  platform_->SetMountEncOutputForArg("info", "not found.");

  startup::CreateSystemKey(base_dir, stateful, platform_.get());

  std::string res;
  base::ReadFileToString(log_file, &res);
  std::string expected =
      "Checking if a system key already exists in NVRAM...\n";
  expected.append("not found.\n");
  expected.append("No system key found in NVRAM. Start creating one.\n");
  expected.append("Failed to generate or back up system key material.\n");
  EXPECT_EQ(res, expected);
}

TEST_F(SysKeyTest, NeedSysKeySuccessful) {
  base::FilePath backup = stateful.Append(kPreserveSysKeyFile);
  ASSERT_TRUE(CreateDirAndWriteFile(log_file, "1"));
  ASSERT_TRUE(CreateDirAndWriteFile(backup, "1"));
  platform_->SetMountEncOutputForArg("info", "not found.");
  platform_->SetMountEncOutputForArg("set", "MountEncrypted set output.\n");
  startup::CreateSystemKey(base_dir, stateful, platform_.get());

  std::string res;
  base::ReadFileToString(log_file, &res);
  std::string expected =
      "Checking if a system key already exists in NVRAM...\n";
  expected.append("not found.\n");
  expected.append("No system key found in NVRAM. Start creating one.\n");
  expected.append("MountEncrypted set output.\n");
  expected.append("Successfully created a system key.");
  EXPECT_EQ(res, expected);
}

class ExceptionsTest : public ::testing::Test {
 protected:
  ExceptionsTest() {}

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base_dir = temp_dir_.GetPath();
    allow_file_ = base_dir.Append("allow_file");
    ASSERT_TRUE(CreateDirAndWriteFile(allow_file_, ""));
    excepts_dir_ = base_dir.Append("excepts_dir");
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath base_dir;
  base::FilePath allow_file_;
  base::FilePath excepts_dir_;
};

TEST_F(ExceptionsTest, ExceptionsDirNoExist) {
  startup::ExceptionsProjectSpecific(base_dir, excepts_dir_,
                                     &ExceptionsTestFunc);
  std::string allow_contents;
  base::ReadFileToString(allow_file_, &allow_contents);
  EXPECT_EQ(allow_contents, "");
}

TEST_F(ExceptionsTest, ExceptionsDirEmpty) {
  base::CreateDirectory(excepts_dir_);
  startup::ExceptionsProjectSpecific(base_dir, excepts_dir_,
                                     &ExceptionsTestFunc);
  std::string allow_contents;
  base::ReadFileToString(allow_file_, &allow_contents);
  EXPECT_EQ(allow_contents, "");
}

TEST_F(ExceptionsTest, ExceptionsDirMultiplePaths) {
  base::FilePath test_path_1_1 = base_dir.Append("test_1_1");
  base::FilePath test_path_1_2 = base_dir.Append("test_1_2");
  base::FilePath test_path_1_ignore = base_dir.Append("should_ignore");
  std::string test_str_1 = std::string("\n")
                               .append(test_path_1_1.value())
                               .append("\n#ignore\n\n#")
                               .append(test_path_1_ignore.value())
                               .append("\n")
                               .append(test_path_1_2.value())
                               .append("\n");
  base::FilePath test_path_2_1 = base_dir.Append("test_2_1");
  base::FilePath test_path_2_2 = base_dir.Append("test_2_2");
  base::FilePath test_path_2_ignore = base_dir.Append("should_ignore");
  std::string test_str_2 = std::string("#")
                               .append(test_path_2_ignore.value())
                               .append("\n")
                               .append(test_path_2_1.value())
                               .append("\n\n#\n")
                               .append(test_path_2_2.value());
  base::FilePath test_1 = excepts_dir_.Append("test_1");
  base::FilePath test_2 = excepts_dir_.Append("test_2");
  ASSERT_TRUE(CreateDirAndWriteFile(test_1, test_str_1));
  ASSERT_TRUE(CreateDirAndWriteFile(test_2, test_str_2));

  startup::ExceptionsProjectSpecific(base_dir, excepts_dir_,
                                     &ExceptionsTestFunc);

  std::string allow_contents;
  base::ReadFileToString(allow_file_, &allow_contents);
  EXPECT_NE(allow_contents.find(test_path_1_1.value()), std::string::npos);
  EXPECT_NE(allow_contents.find(test_path_1_2.value()), std::string::npos);
  EXPECT_EQ(allow_contents.find(test_path_1_ignore.value()), std::string::npos);
  EXPECT_NE(allow_contents.find(test_path_2_1.value()), std::string::npos);
  EXPECT_NE(allow_contents.find(test_path_2_2.value()), std::string::npos);
  EXPECT_EQ(allow_contents.find(test_path_1_ignore.value()), std::string::npos);
  EXPECT_EQ(base::DirectoryExists(test_path_1_1), true);
  EXPECT_EQ(base::DirectoryExists(test_path_1_2), true);
  EXPECT_EQ(base::DirectoryExists(test_path_1_ignore), false);
  EXPECT_EQ(base::DirectoryExists(test_path_2_1), true);
  EXPECT_EQ(base::DirectoryExists(test_path_2_2), true);
  EXPECT_EQ(base::DirectoryExists(test_path_2_ignore), false);
}
