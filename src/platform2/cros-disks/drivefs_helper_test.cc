// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/drivefs_helper.h"

#include <sys/mount.h>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/platform.h"
#include "cros-disks/uri.h"
#include "cros-disks/user.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::DoAll;
using testing::EndsWith;
using testing::HasSubstr;
using testing::Invoke;
using testing::IsSupersetOf;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::StrEq;
using testing::UnorderedElementsAre;

constexpr char kSource[] = "drivefs://id";
constexpr char kDataDir[] = "/home/chronos/user/GCache/foo";
constexpr char kMountPath[] = "/media/fuse/drivefs/id";

constexpr char kPrefixParam[] = "prefix=/media/fuse/drivefs/id";
constexpr char kDataDirParam[] = "datadir=/home/chronos/user/GCache/foo";
constexpr char kMyFilesParam[] = "myfiles=/home/chronos/user/MyFiles";

std::vector<std::string> ParseOptions(const SandboxedProcess& sandbox) {
  CHECK_EQ(2, sandbox.arguments().size());
  CHECK_EQ("-o", sandbox.arguments()[0]);
  return base::SplitString(sandbox.arguments()[1], ",",
                           base::WhitespaceHandling::KEEP_WHITESPACE,
                           base::SplitResult::SPLIT_WANT_ALL);
}

// Mock Platform implementation for testing.
class PlatformForTest : public MockPlatform {
 public:
  PlatformForTest() {
    ON_CALL(*this, GetRealPath(_, _))
        .WillByDefault(Invoke(this, &PlatformForTest::GetRealPathImpl));
    ON_CALL(*this, DirectoryExists(_)).WillByDefault(Return(true));
    ON_CALL(*this, GetOwnership(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<1>(kChronosUID), Return(true)));
  }

  bool GetRealPathImpl(const std::string& path, std::string* real_path) const {
    std::vector<std::string> components = base::FilePath(path).GetComponents();
    base::FilePath result(components[0]);
    components.erase(components.begin());
    for (const auto& part : components) {
      if (part != ".")
        result = result.Append(part);
    }
    *real_path = result.value();
    return true;
  }

  bool GetUserAndGroupId(const std::string& user,
                         uid_t* user_id,
                         gid_t* group_id) const override {
    NOTREACHED();
    return false;
  }

  bool GetGroupId(const std::string& group, gid_t* group_id) const override {
    NOTREACHED();
    return false;
  }

  bool SetOwnership(const std::string&, uid_t, gid_t) const override {
    NOTREACHED();
    return false;
  }
};

class TestDrivefsHelper : public DrivefsHelper {
 public:
  TestDrivefsHelper(const Platform* platform,
                    brillo::ProcessReaper* process_reaper)
      : DrivefsHelper(platform, process_reaper) {}
  using DrivefsHelper::ConfigureSandbox;
};

class DrivefsHelperTest : public ::testing::Test {
 public:
  DrivefsHelperTest() : helper_(&platform_, &process_reaper_) {}

 protected:
  PlatformForTest platform_;
  brillo::ProcessReaper process_reaper_;
  TestDrivefsHelper helper_;
};

TEST_F(DrivefsHelperTest, ConfigureSandbox) {
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(
      kSource, base::FilePath(kMountPath),
      {"datadir=/home/chronos//user/GCache//foo/./"}, &sandbox);

  EXPECT_EQ(MountError::kSuccess, error);
  auto options = ParseOptions(sandbox);
  EXPECT_THAT(options,
              UnorderedElementsAre(kDataDirParam, "identity=id", "uid=1000",
                                   "gid=1001", kPrefixParam));
}

TEST_F(DrivefsHelperTest, ConfigureSandboxWithMyFiles) {
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(
      kSource, base::FilePath(kMountPath),
      {kDataDirParam, "myfiles=/home/chronos//user/.//MyFiles"}, &sandbox);

  EXPECT_EQ(MountError::kSuccess, error);
  auto options = ParseOptions(sandbox);
  EXPECT_THAT(options, IsSupersetOf({StrEq(kMyFilesParam)}));
}

TEST_F(DrivefsHelperTest, ConfigureSandboxFailsIfInvalidSource) {
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(
      "drive://id", base::FilePath(kMountPath), {kDataDirParam}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);

  error = helper_.ConfigureSandbox("/dev/block", base::FilePath(kMountPath),
                                   {kDataDirParam}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);

  error = helper_.ConfigureSandbox("drivefs:/foo", base::FilePath(kMountPath),
                                   {kDataDirParam}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);
}

TEST_F(DrivefsHelperTest, ConfigureSandboxFailsIfDataDirInvalid) {
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath), {},
                                        &sandbox);
  EXPECT_NE(MountError::kSuccess, error);

  error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath),
                                   {"datadir=dodgy/path"}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);

  error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath),
                                   {"datadir=/nonhome/dir"}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);

  error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath),
                                   {"datadir=/home/chronos/../../etc/passwd"},
                                   &sandbox);
  EXPECT_NE(MountError::kSuccess, error);
}

TEST_F(DrivefsHelperTest, ConfigureSandboxFailsIfDataDirDoesntExist) {
  EXPECT_CALL(platform_, DirectoryExists(kDataDir)).WillOnce(Return(false));
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath),
                                        {kDataDirParam}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);
}

TEST_F(DrivefsHelperTest, ConfigureSandboxFailsWhenCantStat) {
  EXPECT_CALL(platform_, GetOwnership(kDataDir, _, _)).WillOnce(Return(false));
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath),
                                        {kDataDirParam}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);
}

TEST_F(DrivefsHelperTest, ConfigureSandboxFailsWhenWrongOwner) {
  EXPECT_CALL(platform_, GetOwnership(kDataDir, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kChronosUID + 100), Return(false)));
  FakeSandboxedProcess sandbox;
  auto error = helper_.ConfigureSandbox(kSource, base::FilePath(kMountPath),
                                        {kDataDirParam}, &sandbox);
  EXPECT_NE(MountError::kSuccess, error);
}

}  // namespace
}  // namespace cros_disks
