// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mock_platform.h"
#include "cryptohome/projectid_config.h"
#include "cryptohome/storage/arc_disk_quota.h"
#include "cryptohome/storage/mock_homedirs.h"

#include <memory>
#include <optional>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/quota.h>
#include <sys/types.h>

#include <libhwsec-foundation/error/testing_helper.h>

using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Ne;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;

namespace cryptohome {

namespace {

constexpr char kDev[] = "/dev/mmcblk0p1";

}  // namespace

class ArcDiskQuotaTest : public ::testing::Test {
 public:
  ArcDiskQuotaTest()
      : arc_disk_quota_(&homedirs_, &platform_, base::FilePath(kArcDiskHome)) {}
  ArcDiskQuotaTest(const ArcDiskQuotaTest&) = delete;
  ArcDiskQuotaTest& operator=(const ArcDiskQuotaTest&) = delete;

  ~ArcDiskQuotaTest() override {}

  void SetUp() override {
    media_rw_data_file_selinux_context_ =
        kMediaRWDataFileSELinuxContextTokens[0];
    for (int i = 1; i < std::size(kMediaRWDataFileSELinuxContextTokens); ++i) {
      media_rw_data_file_selinux_context_ +=
          std::string(":") + kMediaRWDataFileSELinuxContextTokens[i];
    }
  }

 protected:
  MockHomeDirs homedirs_;
  MockPlatform platform_;
  ArcDiskQuota arc_disk_quota_;
  std::string media_rw_data_file_selinux_context_;

  static const uid_t kAndroidUidStart = ArcDiskQuota::kAndroidUidStart;
  static const uid_t kAndroidUidEnd = ArcDiskQuota::kAndroidUidEnd;
  static const gid_t kAndroidGidStart = ArcDiskQuota::kAndroidGidStart;
  static const gid_t kAndroidGidEnd = ArcDiskQuota::kAndroidGidEnd;
  static const uid_t kValidAndroidUid = (kAndroidUidStart + kAndroidUidEnd) / 2;
  static const gid_t kValidAndroidGid = (kAndroidGidStart + kAndroidGidEnd) / 2;
  static const int kValidAndroidProjectId =
      (kProjectIdForAndroidFilesStart + kProjectIdForAndroidFilesEnd) / 2;
  static constexpr char kObfuscatedUsername[] = "cafef00d";
};

TEST_F(ArcDiskQuotaTest, QuotaIsSupported) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  // Exactly 1 Android user.
  EXPECT_CALL(homedirs_, GetUnmountedAndroidDataCount()).WillOnce(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(true, arc_disk_quota_.IsQuotaSupported());
}

TEST_F(ArcDiskQuotaTest, QuotaIsNotSupported_NoDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(false)));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(false, arc_disk_quota_.IsQuotaSupported());
}

TEST_F(ArcDiskQuotaTest, QuotaIsNotSupported_NoQuotaMountedDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(-1));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(false, arc_disk_quota_.IsQuotaSupported());
}

TEST_F(ArcDiskQuotaTest, QuotaIsNotSupported_MultipleAndroidUser) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  // Multiple Android users.
  EXPECT_CALL(homedirs_, GetUnmountedAndroidDataCount()).WillOnce(Return(2));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(false, arc_disk_quota_.IsQuotaSupported());
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForUid_Succeeds) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(
                             base::FilePath(kDev),
                             kValidAndroidUid + kArcContainerShiftUid))
      .WillRepeatedly(Return(5));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(5, arc_disk_quota_.GetCurrentSpaceForUid(kValidAndroidUid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForUid_UidTooSmall) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForUid(kAndroidUidStart - 1));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForUid_UidTooLarge) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForUid(kAndroidUidEnd + 1));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForUid_NoDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(false)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(_, _)).Times(0);

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForUid(kValidAndroidUid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForUid_NoQuotaMountedDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(-1));

  EXPECT_CALL(platform_,
              GetQuotaCurrentSpaceForUid(Ne(base::FilePath(kDev)), Ne(0)))
      .Times(0);

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForUid(kValidAndroidUid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForUid_QuotactlFails) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(
                             base::FilePath(kDev),
                             kValidAndroidUid + kArcContainerShiftUid))
      .WillOnce(Return(-1));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForUid(kValidAndroidUid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForGid_Succeeds) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForGid(
                             base::FilePath(kDev),
                             kValidAndroidGid + kArcContainerShiftGid))
      .WillOnce(Return(5));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(5, arc_disk_quota_.GetCurrentSpaceForGid(kValidAndroidGid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForGid_GidTooSmall) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForGid(kAndroidGidStart - 1));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForGid_GidTooLarge) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForGid(kAndroidGidEnd + 1));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForGid_NoDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(false)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForGid(_, _)).Times(0);

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForGid(kValidAndroidGid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForGid_NoQuotaMountedDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(-1));

  EXPECT_CALL(platform_,
              GetQuotaCurrentSpaceForUid(Ne(base::FilePath(kDev)), Ne(0)))
      .Times(0);

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForGid(kValidAndroidGid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForGid_QuotactlFails) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForGid(
                             base::FilePath(kDev),
                             kValidAndroidGid + kArcContainerShiftGid))
      .WillRepeatedly(Return(-1));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForGid(kValidAndroidGid));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForProjectId_Succeeds) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForProjectId(
                             base::FilePath(kDev), kValidAndroidProjectId))
      .WillOnce(Return(5));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(
      5, arc_disk_quota_.GetCurrentSpaceForProjectId(kValidAndroidProjectId));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForProjectId_IdTooSmall) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForProjectId(
                    kProjectIdForAndroidFilesStart - 1));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForProjectId_IdTooLarge) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(-1, arc_disk_quota_.GetCurrentSpaceForProjectId(
                    kProjectIdForAndroidFilesEnd + 1));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForProjectId_NoDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(""), Return(false)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForProjectId(_, _)).Times(0);

  arc_disk_quota_.Initialize();
  EXPECT_EQ(
      -1, arc_disk_quota_.GetCurrentSpaceForProjectId(kValidAndroidProjectId));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForProjectId_NoQuotaMountedDevice) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(-1));

  EXPECT_CALL(platform_,
              GetQuotaCurrentSpaceForUid(Ne(base::FilePath(kDev)), Ne(0)))
      .Times(0);

  arc_disk_quota_.Initialize();
  EXPECT_EQ(
      -1, arc_disk_quota_.GetCurrentSpaceForProjectId(kValidAndroidProjectId));
}

TEST_F(ArcDiskQuotaTest, GetCurrentSpaceForProjectId_QuotactlFails) {
  EXPECT_CALL(platform_, FindFilesystemDevice(base::FilePath(kArcDiskHome), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(kDev), Return(true)));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForUid(base::FilePath(kDev), 0))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(platform_, GetQuotaCurrentSpaceForProjectId(
                             base::FilePath(kDev), kValidAndroidProjectId))
      .WillOnce(Return(-1));

  arc_disk_quota_.Initialize();
  EXPECT_EQ(
      -1, arc_disk_quota_.GetCurrentSpaceForProjectId(kValidAndroidProjectId));
}


TEST_F(ArcDiskQuotaTest, IsMediaRWDataFileContext_NoCategory) {
  EXPECT_TRUE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_InvalidNumberOfCategories) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c10"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_AppIdCategories) {
  EXPECT_TRUE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c10,c270"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_InvalidFirstAppIdCategories) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c270,c270"));
}

TEST_F(
    ArcDiskQuotaTest,
    IsMediaRWDataFileContext_ContextCategories_InvalidSecondAppIdCategories) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c10,c10"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_UserCategories) {
  EXPECT_TRUE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c512,c768"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_InvalidFirstUserCategories) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c51,c768"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_InvalidSecondUserCategories) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c512,c76"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_ContextCategories_AppIdAndUserCategories) {
  EXPECT_TRUE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c10,c270,c512,c768"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_FourContextCategories_InvalidFirstAppId) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c270,c270,c512,c768"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_FourContextCategories_InvalidSecondAppId) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c123,c10,c512,c768"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_FourContextCategories_InvalidFirstUser) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c123,c258,c515,c768"));
}

TEST_F(ArcDiskQuotaTest,
       IsMediaRWDataFileContext_FourContextCategories_InvalidSecondUser) {
  EXPECT_FALSE(ArcDiskQuota::IsMediaRWDataFileContext(
      media_rw_data_file_selinux_context_ + ":c123,c258,c512,c771"));
}

TEST_F(ArcDiskQuotaTest, SetMediaRWDataFileProjectId_Succeeds) {
  constexpr int kProjectId = kValidAndroidProjectId;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_CALL(platform_, GetSELinuxContextOfFD(kFd))
      .WillOnce(Return(media_rw_data_file_selinux_context_));
  EXPECT_CALL(platform_, SetQuotaProjectIdWithFd(kProjectId, kFd, &error))
      .WillOnce(Return(true));

  EXPECT_TRUE(
      arc_disk_quota_.SetMediaRWDataFileProjectId(kProjectId, kFd, &error));
}

TEST_F(ArcDiskQuotaTest, SetMediaRWDataFileProjectId_IdOutOfAllowedRange) {
  constexpr int kProjectId = kProjectIdForAndroidFilesEnd + 1;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_FALSE(
      arc_disk_quota_.SetMediaRWDataFileProjectId(kProjectId, kFd, &error));
  EXPECT_EQ(error, EINVAL);
}

TEST_F(ArcDiskQuotaTest, SetMediaRWDataFileProjectId_GetSELinuxContextFails) {
  constexpr int kProjectId = kValidAndroidProjectId;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_CALL(platform_, GetSELinuxContextOfFD(kFd))
      .WillOnce(Return(std::nullopt));

  EXPECT_FALSE(
      arc_disk_quota_.SetMediaRWDataFileProjectId(kProjectId, kFd, &error));
  EXPECT_EQ(error, EIO);
}

TEST_F(ArcDiskQuotaTest, SetMediaRWDataFileProjectId_UnexpectedSELinuxContext) {
  constexpr int kProjectId = kValidAndroidProjectId;
  constexpr int kFd = 1234;
  int error = 0;

  constexpr char kUnexpectedSELinuxContext[] = "u:object_r:cros_home_shadow:s0";
  EXPECT_CALL(platform_, GetSELinuxContextOfFD(kFd))
      .WillOnce(Return(kUnexpectedSELinuxContext));

  EXPECT_FALSE(
      arc_disk_quota_.SetMediaRWDataFileProjectId(kProjectId, kFd, &error));
  EXPECT_EQ(error, EPERM);
}

TEST_F(ArcDiskQuotaTest, SetMediaRWDataFileProjectInheritanceFlag_Succeeds) {
  constexpr bool kEnable = true;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_CALL(platform_, GetSELinuxContextOfFD(kFd))
      .WillOnce(Return(media_rw_data_file_selinux_context_));
  EXPECT_CALL(platform_,
              SetQuotaProjectInheritanceFlagWithFd(kEnable, kFd, &error))
      .WillOnce(Return(true));

  EXPECT_TRUE(arc_disk_quota_.SetMediaRWDataFileProjectInheritanceFlag(
      kEnable, kFd, &error));
}

TEST_F(ArcDiskQuotaTest,
       SetMediaRWDataFileProjectInheritanceFlag_GetSELinuxContextFails) {
  constexpr bool kEnable = true;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_CALL(platform_, GetSELinuxContextOfFD(kFd))
      .WillOnce(Return(std::nullopt));

  EXPECT_FALSE(arc_disk_quota_.SetMediaRWDataFileProjectInheritanceFlag(
      kEnable, kFd, &error));
  EXPECT_EQ(error, EIO);
}

TEST_F(ArcDiskQuotaTest,
       SetMediaRWDataFileProjectInheritanceFlag_UnexpectedSELinuxContext) {
  constexpr bool kEnable = true;
  constexpr int kFd = 1234;
  int error = 0;

  constexpr char kUnexpectedSELinuxContext[] = "u:object_r:cros_home_shadow:s0";
  EXPECT_CALL(platform_, GetSELinuxContextOfFD(kFd))
      .WillOnce(Return(kUnexpectedSELinuxContext));

  EXPECT_FALSE(arc_disk_quota_.SetMediaRWDataFileProjectInheritanceFlag(
      kEnable, kFd, &error));
  EXPECT_EQ(error, EPERM);
}

}  // namespace cryptohome
