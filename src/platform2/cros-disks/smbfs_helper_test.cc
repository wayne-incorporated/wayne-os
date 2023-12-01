// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/smbfs_helper.h"

#include <string>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/strings/string_split.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/platform.h"
#include "cros-disks/uri.h"

using testing::_;
using testing::DoAll;
using testing::HasSubstr;
using testing::Return;
using testing::SetArgPointee;
using testing::UnorderedElementsAre;

namespace cros_disks {

namespace {

const base::FilePath kMountDir("/mount_point");
const Uri kSomeSource("smbfs", "foobarbaz");

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
  PlatformForTest() = default;

  bool GetUserAndGroupId(const std::string& name,
                         uid_t* uid,
                         gid_t* gid) const override {
    if (name == "fuse-smbfs") {
      if (uid)
        *uid = 123;
      if (gid)
        *gid = 456;
      return true;
    }
    return false;
  }
};

}  // namespace

class SmbfsHelperTest : public ::testing::Test {
 public:
  SmbfsHelperTest() : helper_(&platform_, &process_reaper_) {}

 protected:
  MountError ConfigureSandbox(const std::string& source,
                              std::vector<std::string>* args) {
    FakeSandboxedProcess sandbox;
    MountError error =
        helper_.ConfigureSandbox(source, kMountDir, {}, &sandbox);
    if (error == MountError::kSuccess) {
      *args = ParseOptions(sandbox);
    }
    return error;
  }

  PlatformForTest platform_;
  brillo::ProcessReaper process_reaper_;
  SmbfsHelper helper_;
};

TEST_F(SmbfsHelperTest, CreateMounter) {
  std::vector<std::string> args;
  EXPECT_EQ(MountError::kSuccess, ConfigureSandbox(kSomeSource.value(), &args));
  EXPECT_THAT(
      args, UnorderedElementsAre("uid=1000", "gid=1001", "mojo_id=foobarbaz"));
}

TEST_F(SmbfsHelperTest, CanMount) {
  base::FilePath name;
  EXPECT_TRUE(helper_.CanMount("smbfs://foo", {}, &name));
  EXPECT_FALSE(helper_.CanMount("smbfss://foo", {}, &name));
  EXPECT_FALSE(helper_.CanMount("smb://foo", {}, &name));
  EXPECT_TRUE(helper_.CanMount("smbfs://", {}, &name));
}

}  // namespace cros_disks
