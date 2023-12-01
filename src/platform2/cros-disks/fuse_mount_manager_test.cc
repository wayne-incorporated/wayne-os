// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/fuse_mount_manager.h"

#include <sys/mount.h>

#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_util.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/metrics.h"
#include "cros-disks/mock_platform.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"
#include "cros-disks/sandboxed_process.h"
#include "cros-disks/uri.h"

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::WithArg;

namespace cros_disks {

namespace {

const char kMountRoot[] = "/mntroot";
const char kWorkingDirRoot[] = "/wkdir";
const char kNoType[] = "";
const char kSomeMountpoint[] = "/mnt";
const Uri kSomeSource("fuse", "something");

// Mock implementation of a Mounter.
class MockMounter : public Mounter {
 public:
  MOCK_METHOD(std::unique_ptr<MountPoint>,
              Mount,
              (const std::string& source,
               const base::FilePath& target_path,
               std::vector<std::string> params,
               MountError* error),
              (const, override));
  MOCK_METHOD(bool,
              CanMount,
              (const std::string& source,
               const std::vector<std::string>& params,
               base::FilePath* suggested_dir_name),
              (const, override));
};

class MockSandboxedProcess : public SandboxedProcess {
 public:
  MockSandboxedProcess() = default;
  pid_t StartImpl(base::ScopedFD, base::ScopedFD) override { return 123; }
  MOCK_METHOD(int, WaitImpl, (), (override));
  MOCK_METHOD(int, WaitNonBlockingImpl, (), (override));
};

}  // namespace

class FUSEMountManagerTest : public ::testing::Test {
 public:
  FUSEMountManagerTest()
      : manager_(kMountRoot,
                 kWorkingDirRoot,
                 &platform_,
                 &metrics_,
                 &process_reaper_),
        foo_(new MockMounter()),
        bar_(new MockMounter()),
        baz_(new MockMounter()) {
    ON_CALL(platform_, Unmount(_, _))
        .WillByDefault(Return(MountError::kInvalidArgument));
    ON_CALL(platform_, DirectoryExists(_)).WillByDefault(Return(true));
  }

 protected:
  void RegisterHelper(std::unique_ptr<Mounter> helper) {
    manager_.RegisterHelper(std::move(helper));
  }

  std::unique_ptr<MountPoint> DoMount(const std::string& type,
                                      const std::string& src,
                                      MountError* error) {
    std::unique_ptr<MountPoint> mount_point =
        manager_.DoMount(src, type, {}, base::FilePath(kSomeMountpoint), error);
    if (*error == MountError::kSuccess) {
      EXPECT_TRUE(mount_point);
    } else {
      EXPECT_FALSE(mount_point);
    }
    return mount_point;
  }

  Metrics metrics_;
  MockPlatform platform_;
  brillo::ProcessReaper process_reaper_;
  FUSEMountManager manager_;
  std::unique_ptr<MockMounter> foo_;
  std::unique_ptr<MockMounter> bar_;
  std::unique_ptr<MockMounter> baz_;
};

// Verifies that CanMount returns false when there are no handlers registered.
TEST_F(FUSEMountManagerTest, CanMount_NoHandlers) {
  EXPECT_FALSE(manager_.CanMount(kSomeSource.value()));
}

// Verifies that CanMount returns false when known helpers can't handle that.
TEST_F(FUSEMountManagerTest, CanMount_NotHandled) {
  EXPECT_CALL(*foo_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*bar_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*baz_, CanMount).WillOnce(Return(false));
  RegisterHelper(std::move(foo_));
  RegisterHelper(std::move(bar_));
  RegisterHelper(std::move(baz_));
  EXPECT_FALSE(manager_.CanMount(kSomeSource.value()));
}

// Verify that CanMount returns true when there is a helper that can handle
// this source.
TEST_F(FUSEMountManagerTest, CanMount) {
  EXPECT_CALL(*foo_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*bar_, CanMount).WillOnce(Return(true));
  EXPECT_CALL(*baz_, CanMount).Times(0);
  RegisterHelper(std::move(foo_));
  RegisterHelper(std::move(bar_));
  RegisterHelper(std::move(baz_));
  EXPECT_TRUE(manager_.CanMount(kSomeSource.value()));
}

// Verify that SuggestMountPath dispatches query for name to the correct helper.
TEST_F(FUSEMountManagerTest, SuggestMountPath) {
  EXPECT_CALL(*foo_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*bar_, CanMount)
      .WillOnce(
          DoAll(SetArgPointee<2>(base::FilePath("suffix")), Return(true)));
  EXPECT_CALL(*baz_, CanMount).Times(0);
  RegisterHelper(std::move(foo_));
  RegisterHelper(std::move(bar_));
  RegisterHelper(std::move(baz_));
  EXPECT_EQ("/mntroot/suffix", manager_.SuggestMountPath(kSomeSource.value()));
}

// Verify that DoMount fails when there are no helpers.
TEST_F(FUSEMountManagerTest, DoMount_NoHandlers) {
  MountError mount_error;
  std::unique_ptr<MountPoint> mount_point =
      DoMount(kNoType, kSomeSource.value(), &mount_error);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error);
}

// Verify that DoMount fails when helpers don't handle this source.
TEST_F(FUSEMountManagerTest, DoMount_NotHandled) {
  EXPECT_CALL(*foo_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*bar_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*baz_, CanMount).WillOnce(Return(false));
  RegisterHelper(std::move(foo_));
  RegisterHelper(std::move(bar_));
  RegisterHelper(std::move(baz_));
  MountError mount_error;
  std::unique_ptr<MountPoint> mount_point =
      DoMount(kNoType, kSomeSource.value(), &mount_error);
  EXPECT_EQ(MountError::kUnknownFilesystem, mount_error);
}

// Verify that DoMount delegates mounting to the correct helpers when
// dispatching by source description.
TEST_F(FUSEMountManagerTest, DoMount_BySource) {
  EXPECT_CALL(*foo_, CanMount).WillOnce(Return(false));
  EXPECT_CALL(*bar_, CanMount)
      .WillOnce(
          DoAll(SetArgPointee<2>(base::FilePath("suffix")), Return(true)));
  EXPECT_CALL(*baz_, CanMount).Times(0);

  EXPECT_CALL(*foo_, Mount).Times(0);
  EXPECT_CALL(*baz_, Mount).Times(0);

  EXPECT_CALL(*bar_, Mount(kSomeSource.value(), _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(MountError::kSuccess),
                      Return(ByMove(MountPoint::CreateUnmounted(
                          {.mount_path = base::FilePath(kSomeMountpoint),
                           .source = kSomeSource.value()})))));

  RegisterHelper(std::move(foo_));
  RegisterHelper(std::move(bar_));
  RegisterHelper(std::move(baz_));
  MountError mount_error;
  std::unique_ptr<MountPoint> mount_point =
      DoMount(kNoType, kSomeSource.value(), &mount_error);
  EXPECT_EQ(MountError::kSuccess, mount_error);
  EXPECT_EQ(base::FilePath(kSomeMountpoint), mount_point->path());
}

}  // namespace cros_disks
