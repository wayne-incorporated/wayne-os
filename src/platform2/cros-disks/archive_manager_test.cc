// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/archive_manager.h"

#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/metrics.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/platform.h"
#include "cros-disks/user.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::IsEmpty;
using testing::Return;
using testing::SetArgPointee;
using testing::UnorderedElementsAre;

const char kMountRootDirectory[] = "/my_mount_point";

}  // namespace

class ArchiveManagerUnderTest : public ArchiveManager {
 public:
  using ArchiveManager::ArchiveManager;
  ~ArchiveManagerUnderTest() override { UnmountAll(); }

  MOCK_METHOD(bool, CanMount, (const std::string&), (const, override));
  MOCK_METHOD(std::unique_ptr<MountPoint>,
              DoMount,
              (const std::string&,
               const std::string&,
               const std::vector<std::string>&,
               const base::FilePath&,
               MountError*),
              (override));

  using ArchiveManager::CreateSandboxFactory;
};

class ArchiveManagerTest : public testing::Test {
 protected:
  Metrics metrics_;
  MockPlatform platform_;
  brillo::ProcessReaper reaper_;
  const ArchiveManagerUnderTest manager_{kMountRootDirectory, &platform_,
                                         &metrics_, &reaper_};
};

TEST_F(ArchiveManagerTest, IsInAllowedFolder) {
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(""));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/dev/sda1"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/MyFiles/foo"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/MyFiles/x/"
      "foo"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/MyFiles/"
      "Downloads/foo"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/MyFiles/"
      "Downloads/x/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/x/foo"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/user/MyFiles/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/homex/chronos/u-0123456789abcdef0123456789abcdef01234567/MyFiles/"
      "Downloads/x/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronosx/u-0123456789abcdef0123456789abcdef01234567/MyFiles/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/0123456789abcdef0123456789abcdef01234567/MyFiles/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567x/MyFiles/foo"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/user/Downloads/bar"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/MyFiles/"
      "Downloads/bar"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/media/removable"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/media/removable/"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/media/archive"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/media/archive/"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/user/Downloads"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/user/Downloads/"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/Downloads"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/Downloads/"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/home/chronos/bar"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/home/chronos/user/bar"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef01234567/bar"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/Downloads/bar"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/foo/Downloads/bar"));
  EXPECT_FALSE(
      ArchiveManager::IsInAllowedFolder("/home/chronos/u-/Downloads/bar"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-0123456789abcdef0123456789abcdef0123456/Downloads/bar"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder(
      "/home/chronos/u-xyz3456789abcdef0123456789abcdef01234567/Downloads/"
      "bar"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder("/media/archive/y/foo"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder("/media/fuse/y/foo"));
  EXPECT_TRUE(ArchiveManager::IsInAllowedFolder("/media/removable/y/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/media/x/y/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("/media/x/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("x/media/fuse/y/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("media/fuse/y/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("file:///media/fuse/y/foo"));
  EXPECT_FALSE(ArchiveManager::IsInAllowedFolder("ssh:///media/fuse/y/foo"));
}

TEST_F(ArchiveManagerTest, GetMountSourceType) {
  EXPECT_EQ(manager_.GetMountSourceType(), MOUNT_SOURCE_ARCHIVE);
}

TEST_F(ArchiveManagerTest, SuggestMountPath) {
  EXPECT_EQ(manager_.SuggestMountPath("/home/chronos/Downloads/My Doc.rar"),
            std::string(kMountRootDirectory) + "/My Doc.rar");
  EXPECT_EQ(manager_.SuggestMountPath("/media/archive/Test.rar/My Doc.zip"),
            std::string(kMountRootDirectory) + "/My Doc.zip");
}

TEST_F(ArchiveManagerTest, GetSupplementaryGroups) {
  const gid_t gid = 478785;
  EXPECT_CALL(platform_, GetGroupId("android-everybody", _))
      .WillOnce(DoAll(SetArgPointee<1>(gid), Return(true)));
  EXPECT_THAT(manager_.GetSupplementaryGroups(), UnorderedElementsAre(gid));
}

TEST_F(ArchiveManagerTest, GetSupplementaryGroupsCannotGetGroupId) {
  EXPECT_CALL(platform_, GetGroupId("android-everybody", _))
      .WillOnce(Return(false));
  EXPECT_THAT(manager_.GetSupplementaryGroups(), IsEmpty());
}

TEST_F(ArchiveManagerTest, CreateSandboxFactory) {
  EXPECT_CALL(platform_, GetUserAndGroupId("fuse-zip", _, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(300), SetArgPointee<2>(301), Return(true)));
  auto zip_sandbox =
      manager_.CreateSandboxFactory({base::FilePath("/foo")}, "fuse-zip");
  EXPECT_EQ(kChronosAccessGID, zip_sandbox->run_as().gid);
  EXPECT_CALL(platform_, GetUserAndGroupId("fuse-rar2fs", _, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(400), SetArgPointee<2>(401), Return(true)));
  auto rar_sandbox =
      manager_.CreateSandboxFactory({base::FilePath("/foo")}, "fuse-rar2fs");
  EXPECT_EQ(kChronosAccessGID, rar_sandbox->run_as().gid);
}

}  // namespace cros_disks
