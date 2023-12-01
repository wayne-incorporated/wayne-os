// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/mount.h>

// The include for sys/mount.h must come before this.
#include <linux/fs.h>

#include <memory>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "init/startup/constants.h"
#include "init/startup/mock_platform_impl.h"
#include "init/startup/uefi_startup.h"
#include "init/startup/uefi_startup_impl.h"

using testing::_;
using testing::Return;
using testing::StrictMock;

namespace startup {

bool operator==(const UefiDelegate::UserAndGroup& lhs,
                const UefiDelegate::UserAndGroup& rhs) {
  return lhs.uid == rhs.uid && lhs.gid == rhs.gid;
}

class MockUefiDelegate : public UefiDelegate {
 public:
  MockUefiDelegate() = default;

  MOCK_METHOD(bool, IsUefiEnabled, (), (const, override));
  MOCK_METHOD(std::optional<UserAndGroup>,
              GetFwupdUserAndGroup,
              (),
              (const, override));
  MOCK_METHOD(bool, MountEfivarfs, (), (override));
  MOCK_METHOD(bool,
              MakeUefiVarWritableByFwupd,
              (const std::string& vendor,
               const std::string& name,
               const UserAndGroup& fwupd),
              (override));
  MOCK_METHOD(bool,
              MountEfiSystemPartition,
              (const UserAndGroup& fwupd),
              (override));
};

// Test that the appropriate actions are taken if UEFI is enabled.
TEST(UefiStartup, UefiEnabled) {
  StrictMock<MockUefiDelegate> mock_uefi_delegate;

  UefiDelegate::UserAndGroup fwupd{1, 2};

  EXPECT_CALL(mock_uefi_delegate, IsUefiEnabled()).WillOnce(Return(true));
  EXPECT_CALL(mock_uefi_delegate, GetFwupdUserAndGroup())
      .WillOnce(Return(fwupd));
  EXPECT_CALL(mock_uefi_delegate, MountEfivarfs()).WillOnce(Return(true));
  EXPECT_CALL(
      mock_uefi_delegate,
      MakeUefiVarWritableByFwupd(kEfiImageSecurityDatabaseGuid, "dbx", fwupd))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_uefi_delegate,
              MountEfiSystemPartition(UefiDelegate::UserAndGroup{1, 2}))
      .WillOnce(Return(true));

  MaybeRunUefiStartup(mock_uefi_delegate);
}

// Test that nothing happens if UEFI is not enabled.
TEST(UefiStartup, UefiDisabled) {
  StrictMock<MockUefiDelegate> mock_uefi_delegate;

  EXPECT_CALL(mock_uefi_delegate, IsUefiEnabled()).WillOnce(Return(false));

  MaybeRunUefiStartup(mock_uefi_delegate);
}

class UefiDelegateTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    root_dir_ = temp_dir_.GetPath();

    uefi_delegate_ =
        std::make_unique<UefiDelegateImpl>(mock_platform_, root_dir_);
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath root_dir_;

  StrictMock<MockPlatform> mock_platform_;
  std::unique_ptr<UefiDelegate> uefi_delegate_;
};

// Test `IsUefiEnabled` when UEFI is enabled.
TEST_F(UefiDelegateTest, IsUefiEnabledYes) {
  const base::FilePath efivars_dir = root_dir_.Append(kEfivarsDir);
  ASSERT_TRUE(base::CreateDirectory(efivars_dir));

  EXPECT_TRUE(uefi_delegate_->IsUefiEnabled());
}

// Test `IsUefiEnabled` when UEFI is not enabled.
TEST_F(UefiDelegateTest, IsUefiEnabledNo) {
  const base::FilePath efivars_dir = root_dir_.Append("sys/firmware");
  ASSERT_TRUE(base::CreateDirectory(efivars_dir));

  EXPECT_FALSE(uefi_delegate_->IsUefiEnabled());
}

// Test mounting efivarfs.
TEST_F(UefiDelegateTest, MountEfivarfs) {
  const base::FilePath efivars_dir = root_dir_.Append(kEfivarsDir);
  ASSERT_TRUE(base::CreateDirectory(efivars_dir));

  EXPECT_CALL(mock_platform_, Mount(kFsTypeEfivarfs, efivars_dir,
                                    kFsTypeEfivarfs, kCommonMountFlags, ""))
      .WillOnce(Return(true));

  EXPECT_TRUE(uefi_delegate_->MountEfivarfs());
}

// Test modifying a UEFI var.
TEST_F(UefiDelegateTest, ModifyVar) {
  const base::FilePath efivars_dir = root_dir_.Append(kEfivarsDir);
  ASSERT_TRUE(base::CreateDirectory(efivars_dir));

  const base::FilePath var_path =
      efivars_dir.Append("myvar-1a2a2d4e-6e6a-468f-944c-c00d14d92c1e");
  ASSERT_TRUE(base::WriteFile(var_path, ""));

  EXPECT_CALL(mock_platform_, Open(var_path, O_RDONLY | O_CLOEXEC))
      .WillOnce(Return(base::ScopedFD(
          HANDLE_EINTR(open(var_path.value().c_str(), O_RDONLY | O_CLOEXEC)))));

  EXPECT_CALL(mock_platform_, Ioctl(_, FS_IOC_GETFLAGS, _)).WillOnce(Return(0));
  EXPECT_CALL(mock_platform_, Ioctl(_, FS_IOC_SETFLAGS, _)).WillOnce(Return(0));
  EXPECT_CALL(mock_platform_, Fchown(_, 123, 456)).WillOnce(Return(true));

  EXPECT_TRUE(uefi_delegate_->MakeUefiVarWritableByFwupd(
      "1a2a2d4e-6e6a-468f-944c-c00d14d92c1e", "myvar",
      UefiDelegate::UserAndGroup{123, 456}));
}

// Test modifying a UEFI var that doesn't exist.
TEST_F(UefiDelegateTest, ModifyInvalidVar) {
  const base::FilePath efivars_dir = root_dir_.Append(kEfivarsDir);
  const base::FilePath var_path =
      efivars_dir.Append("myvar-1a2a2d4e-6e6a-468f-944c-c00d14d92c1e");

  EXPECT_CALL(mock_platform_, Open(var_path, O_RDONLY | O_CLOEXEC))
      .WillOnce(Return(base::ScopedFD()));

  EXPECT_FALSE(uefi_delegate_->MakeUefiVarWritableByFwupd(
      "1a2a2d4e-6e6a-468f-944c-c00d14d92c1e", "myvar",
      UefiDelegate::UserAndGroup{123, 456}));
}

// Test mounting the ESP.
TEST_F(UefiDelegateTest, MountEfiSystemPartition) {
  ASSERT_TRUE(base::CreateDirectory(root_dir_.Append("run")));

  const base::FilePath esp_dir = root_dir_.Append(kEspDir);

  EXPECT_CALL(mock_platform_, GetRootDevicePartitionPath(kEspLabel))
      .WillOnce(Return(base::FilePath("/dev/sda12")));
  EXPECT_CALL(mock_platform_,
              Mount(base::FilePath("/dev/sda12"), esp_dir, kFsTypeVfat,
                    kCommonMountFlags, "uid=123,gid=456,umask=007"))
      .WillOnce(Return(true));

  EXPECT_TRUE(uefi_delegate_->MountEfiSystemPartition(
      UefiDelegate::UserAndGroup{123, 456}));
}

}  // namespace startup
