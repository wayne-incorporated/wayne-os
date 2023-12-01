// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/fuse_mounter.h"

#include <sys/mount.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/mock_platform.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/sandboxed_process.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::ElementsAre;
using testing::EndsWith;
using testing::Invoke;
using testing::IsEmpty;
using testing::Return;
using testing::SetArgPointee;
using testing::StartsWith;

const uid_t kMountUID = 200;
const gid_t kMountGID = 201;
const char kMountUser[] = "fuse-fuse";
const char kFUSEType[] = "fusefs";
const char kSomeSource[] = "/dev/dummy";
const char kMountDir[] = "/mnt";
const char kCgroup[] = "/sys/fs/cgroup/freezer/exe/cgroup.procs";
const int kFUSEMountFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;

// Mock Platform implementation for testing.
class MockFUSEPlatform : public MockPlatform {
 public:
  MockFUSEPlatform() {
    ON_CALL(*this, GetUserAndGroupId(_, _, _))
        .WillByDefault(Invoke(this, &MockFUSEPlatform::GetUserAndGroupIdImpl));
    ON_CALL(*this, PathExists(_)).WillByDefault(Return(true));
    ON_CALL(*this, SetOwnership(_, _, _)).WillByDefault(Return(true));
    ON_CALL(*this, SetPermissions(_, _)).WillByDefault(Return(true));
  }

  bool Lstat(const std::string& path,
             base::stat_wrapper_t* out) const override {
    if (base::StartsWith(path, "/dev/", base::CompareCase::SENSITIVE)) {
      out->st_mode = S_IFBLK | 0640;
      return true;
    }
    return false;
  }

 private:
  bool GetUserAndGroupIdImpl(const std::string& user,
                             uid_t* user_id,
                             gid_t* group_id) const {
    if (user == kMountUser) {
      if (user_id)
        *user_id = kMountUID;
      if (group_id)
        *group_id = kMountGID;
      return true;
    }
    return false;
  }
};

class MockSandboxedProcess : public SandboxedProcess {
 public:
  MockSandboxedProcess() = default;
  MOCK_METHOD(pid_t, StartImpl, (base::ScopedFD, base::ScopedFD), (override));
  MOCK_METHOD(int, WaitImpl, (), (override));
  MOCK_METHOD(int, WaitNonBlockingImpl, (), (override));
  using SandboxedProcess::OnLauncherExit;
};

class FUSEMounterForTesting : public FUSEMounter {
 public:
  FUSEMounterForTesting(const Platform* platform,
                        brillo::ProcessReaper* process_reaper)
      : FUSEMounter(platform, process_reaper, kFUSEType, {}) {}

  MOCK_METHOD(std::unique_ptr<SandboxedProcess>,
              PrepareSandbox,
              (const std::string& source,
               const base::FilePath& target_path,
               std::vector<std::string> params,
               MountError* error),
              (const override));

  bool CanMount(const std::string& source,
                const std::vector<std::string>& params,
                base::FilePath* suggested_dir_name) const override {
    NOTREACHED();
    return true;
  }
};

}  // namespace

class FUSESandboxedProcessFactoryTest : public ::testing::Test {
 public:
  FUSESandboxedProcessFactoryTest() {}

 protected:
  static bool ApplyConfiguration(const FUSESandboxedProcessFactory& factory,
                                 SandboxedProcess* sandbox) {
    return factory.ConfigureSandbox(sandbox);
  }

  MockFUSEPlatform platform_;
  const base::FilePath exe_{"/bin/exe"};
  const OwnerUser run_as_{123, 456};
};

TEST_F(FUSESandboxedProcessFactoryTest, BasicSetup) {
  EXPECT_CALL(platform_, PathExists(kCgroup)).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(exe_.value())).WillOnce(Return(true));
  FUSESandboxedProcessFactory factory(&platform_, {exe_}, run_as_);
  MockSandboxedProcess sandbox_;
  EXPECT_TRUE(ApplyConfiguration(factory, &sandbox_));
}

TEST_F(FUSESandboxedProcessFactoryTest, BasicSetup_MissingExecutable) {
  EXPECT_CALL(platform_, PathExists(kCgroup)).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(exe_.value())).WillOnce(Return(false));
  FUSESandboxedProcessFactory factory(&platform_, {exe_}, run_as_);
  MockSandboxedProcess sandbox_;
  EXPECT_FALSE(ApplyConfiguration(factory, &sandbox_));
}

// TODO(crbug.com/1149685): Disabled as seccomp crashes qemu used for ARM.
TEST_F(FUSESandboxedProcessFactoryTest, DISABLED_SeccompPolicy) {
  base::ScopedTempDir tmp;
  ASSERT_TRUE(tmp.CreateUniqueTempDir());
  base::FilePath seccomp = tmp.GetPath().Append("exe.policy");
  std::string policy = "close: 1\n";
  base::WriteFile(seccomp, policy.c_str(), policy.length());
  EXPECT_CALL(platform_, PathExists(seccomp.value())).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(kCgroup)).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(exe_.value())).WillOnce(Return(true));
  FUSESandboxedProcessFactory factory(&platform_, {exe_, seccomp}, run_as_);
  MockSandboxedProcess sandbox_;
  EXPECT_TRUE(ApplyConfiguration(factory, &sandbox_));
}

TEST_F(FUSESandboxedProcessFactoryTest, SeccompPolicy_MissingPolicy) {
  base::ScopedTempDir tmp;
  ASSERT_TRUE(tmp.CreateUniqueTempDir());
  base::FilePath seccomp = tmp.GetPath().Append("exe.policy");
  EXPECT_CALL(platform_, PathExists(kCgroup)).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(seccomp.value())).WillOnce(Return(false));
  FUSESandboxedProcessFactory factory(&platform_, {exe_, seccomp}, run_as_);
  MockSandboxedProcess sandbox_;
  EXPECT_FALSE(ApplyConfiguration(factory, &sandbox_));
}

TEST_F(FUSESandboxedProcessFactoryTest, NetworkEnabled_NonCrostini) {
  EXPECT_CALL(platform_, PathExists(kCgroup)).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(exe_.value())).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("/etc/hosts.d")).WillOnce(Return(false));
  FUSESandboxedProcessFactory factory(&platform_, {exe_}, run_as_, true);
  MockSandboxedProcess sandbox_;
  EXPECT_TRUE(ApplyConfiguration(factory, &sandbox_));
}

TEST_F(FUSESandboxedProcessFactoryTest, NetworkEnabled_Crostini) {
  EXPECT_CALL(platform_, PathExists(kCgroup)).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists(exe_.value())).WillOnce(Return(true));
  EXPECT_CALL(platform_, PathExists("/etc/hosts.d")).WillOnce(Return(true));
  FUSESandboxedProcessFactory factory(&platform_, {exe_}, run_as_, true);
  MockSandboxedProcess sandbox_;
  EXPECT_TRUE(ApplyConfiguration(factory, &sandbox_));
}

TEST_F(FUSESandboxedProcessFactoryTest, SupplementaryGroups) {
  FUSESandboxedProcessFactory factory(&platform_, {exe_}, run_as_, false, false,
                                      {11, 22, 33});
  MockSandboxedProcess sandbox_;
  EXPECT_TRUE(ApplyConfiguration(factory, &sandbox_));
}

TEST_F(FUSESandboxedProcessFactoryTest, MountNamespace) {
  base::FilePath mount_ns(base::StringPrintf("/proc/%d/ns/mnt", getpid()));
  FUSESandboxedProcessFactory factory(&platform_, {exe_}, run_as_, false, false,
                                      {}, mount_ns);
  MockSandboxedProcess sandbox_;
  EXPECT_TRUE(ApplyConfiguration(factory, &sandbox_));
}

class FUSEMounterTest : public ::testing::Test {
 public:
  FUSEMounterTest() : mounter_(&platform_, &process_reaper_) {}

 protected:
  testing::StrictMock<MockFUSEPlatform> platform_;
  brillo::ProcessReaper process_reaper_;
  using Environment = base::test::TaskEnvironment;
  Environment task_environment_{Environment::MainThreadType::IO};
  FUSEMounterForTesting mounter_;
};

TEST_F(FUSEMounterTest, MountingSucceeds) {
  EXPECT_CALL(platform_,
              Mount("source", kMountDir, "fuse.fusefs",
                    kFUSEMountFlags | MS_NOSYMFOLLOW,
                    EndsWith(",user_id=1000,group_id=1001,allow_other,default_"
                             "permissions,rootmode=40000")))
      .WillOnce(Return(MountError::kSuccess));
  auto process_ptr = std::make_unique<MockSandboxedProcess>();
  MockSandboxedProcess& process = *process_ptr;
  EXPECT_CALL(process, StartImpl).WillOnce(Return(123));
  EXPECT_CALL(mounter_, PrepareSandbox("source", base::FilePath(kMountDir),
                                       ElementsAre("arg1", "arg2", "arg3"), _))
      .WillOnce(Return(ByMove(std::move(process_ptr))));

  MountError error = MountError::kUnknownError;
  auto mount_point = mounter_.Mount("source", base::FilePath(kMountDir),
                                    {"arg1", "arg2", "arg3"}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  EXPECT_TRUE(mount_point);
  EXPECT_EQ(MountError::kInProgress, mount_point->error());
  EXPECT_EQ(base::FilePath(kMountDir), mount_point->path());
  EXPECT_EQ("source", mount_point->source());

  // Simulate asynchronous termination of FUSE launcher process.
  EXPECT_CALL(process, WaitNonBlockingImpl).WillOnce(Return(0));
  process.OnLauncherExit();
  EXPECT_EQ(MountError::kSuccess, mount_point->error());

  // The MountPoint will unmount when it is destructed.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuse.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));
}

TEST_F(FUSEMounterTest, MountingReadOnly) {
  EXPECT_CALL(platform_, Mount(_, kMountDir, _,
                               kFUSEMountFlags | MS_NOSYMFOLLOW | MS_RDONLY, _))
      .WillOnce(Return(MountError::kSuccess));
  auto process_ptr = std::make_unique<MockSandboxedProcess>();
  MockSandboxedProcess& process = *process_ptr;
  EXPECT_CALL(process, StartImpl).WillOnce(Return(123));
  EXPECT_CALL(mounter_, PrepareSandbox(kSomeSource, base::FilePath(kMountDir),
                                       ElementsAre("arg1", "arg2", "ro"), _))
      .WillOnce(Return(ByMove(std::move(process_ptr))));

  MountError error = MountError::kUnknownError;
  auto mount_point = mounter_.Mount(kSomeSource, base::FilePath(kMountDir),
                                    {"arg1", "arg2", "ro"}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  EXPECT_TRUE(mount_point);
  EXPECT_EQ(MountError::kInProgress, mount_point->error());

  // Simulate asynchronous termination of FUSE launcher process.
  EXPECT_CALL(process, WaitNonBlockingImpl).WillOnce(Return(0));
  process.OnLauncherExit();
  EXPECT_EQ(MountError::kSuccess, mount_point->error());

  // The MountPoint will unmount when it is destructed.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));
}

TEST_F(FUSEMounterTest, MountingBlockDevice) {
  EXPECT_CALL(platform_,
              Mount("/dev/foobar", kMountDir, "fuseblk.fusefs",
                    kFUSEMountFlags | MS_NOSYMFOLLOW,
                    EndsWith(",user_id=1000,group_id=1001,allow_other,default_"
                             "permissions,rootmode=40000")))
      .WillOnce(Return(MountError::kSuccess));
  auto process_ptr = std::make_unique<MockSandboxedProcess>();
  MockSandboxedProcess& process = *process_ptr;
  EXPECT_CALL(process, StartImpl).WillOnce(Return(123));
  EXPECT_CALL(mounter_,
              PrepareSandbox("/dev/foobar", base::FilePath(kMountDir), _, _))
      .WillOnce(Return(ByMove(std::move(process_ptr))));

  MountError error = MountError::kUnknownError;
  auto mount_point =
      mounter_.Mount("/dev/foobar", base::FilePath(kMountDir), {}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  EXPECT_TRUE(mount_point);
  EXPECT_EQ(MountError::kInProgress, mount_point->error());

  // Simulate asynchronous termination of FUSE launcher process.
  EXPECT_CALL(process, WaitNonBlockingImpl).WillOnce(Return(0));
  process.OnLauncherExit();
  EXPECT_EQ(MountError::kSuccess, mount_point->error());

  // The MountPoint will unmount when it is destructed.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));
}

TEST_F(FUSEMounterTest, MountFailed) {
  EXPECT_CALL(platform_, Mount(_, kMountDir, _, _, _))
      .WillOnce(Return(MountError::kUnknownFilesystem));
  EXPECT_CALL(mounter_, PrepareSandbox).Times(0);
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .Times(0);

  MountError error = MountError::kUnknownError;
  auto mount_point =
      mounter_.Mount(kSomeSource, base::FilePath(kMountDir), {}, &error);
  EXPECT_FALSE(mount_point);
  EXPECT_EQ(MountError::kUnknownFilesystem, error);
}

TEST_F(FUSEMounterTest, SandboxFailed) {
  EXPECT_CALL(platform_, Mount(_, kMountDir, _, _, _))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(mounter_, PrepareSandbox)
      .WillOnce(DoAll(SetArgPointee<3>(MountError::kInvalidMountOptions),
                      Return(ByMove(nullptr))));
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));

  MountError error = MountError::kUnknownError;
  auto mount_point =
      mounter_.Mount(kSomeSource, base::FilePath(kMountDir), {}, &error);
  EXPECT_FALSE(mount_point);
  EXPECT_EQ(MountError::kInvalidMountOptions, error);
}

TEST_F(FUSEMounterTest, AppFailed) {
  EXPECT_CALL(platform_, Mount(_, kMountDir, _, _, _))
      .WillOnce(Return(MountError::kSuccess));
  auto process_ptr = std::make_unique<MockSandboxedProcess>();
  MockSandboxedProcess& process = *process_ptr;
  EXPECT_CALL(mounter_, PrepareSandbox(_, base::FilePath(kMountDir), _, _))
      .WillOnce(Return(ByMove(std::move(process_ptr))));
  EXPECT_CALL(process, StartImpl).WillOnce(Return(123));

  MountError error = MountError::kUnknownError;
  auto mount_point =
      mounter_.Mount(kSomeSource, base::FilePath(kMountDir), {}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  EXPECT_TRUE(mount_point);
  EXPECT_EQ(MountError::kInProgress, mount_point->error());

  // Simulate asynchronous termination of FUSE launcher process.
  EXPECT_CALL(process, WaitNonBlockingImpl).WillOnce(Return(1));
  process.OnLauncherExit();
  EXPECT_EQ(MountError::kMountProgramFailed, mount_point->error());

  // The MountPoint will unmount when it is destructed.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));
}

TEST_F(FUSEMounterTest, UnmountTwice) {
  EXPECT_CALL(platform_, Mount(_, kMountDir, _, _, _))
      .WillOnce(Return(MountError::kSuccess));
  auto process_ptr = std::make_unique<MockSandboxedProcess>();
  EXPECT_CALL(*process_ptr, StartImpl).WillOnce(Return(123));
  EXPECT_CALL(mounter_, PrepareSandbox(_, base::FilePath(kMountDir), _, _))
      .WillOnce(Return(ByMove(std::move(process_ptr))));

  MountError error = MountError::kUnknownError;
  auto mount_point =
      mounter_.Mount(kSomeSource, base::FilePath(kMountDir), {}, &error);
  EXPECT_TRUE(mount_point);
  EXPECT_EQ(MountError::kSuccess, error);

  // Even though Unmount() is called twice, the underlying unmount should only
  // be done once.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, mount_point->Unmount());
  EXPECT_EQ(MountError::kPathNotMounted, mount_point->Unmount());
}

TEST_F(FUSEMounterTest, UnmountFailure) {
  EXPECT_CALL(platform_, Mount(_, kMountDir, _, _, _))
      .WillOnce(Return(MountError::kSuccess));
  auto process_ptr = std::make_unique<MockSandboxedProcess>();
  EXPECT_CALL(*process_ptr, StartImpl).WillOnce(Return(123));
  EXPECT_CALL(mounter_, PrepareSandbox(_, base::FilePath(kMountDir), _, _))
      .WillOnce(Return(ByMove(std::move(process_ptr))));

  MountError error = MountError::kUnknownError;
  auto mount_point =
      mounter_.Mount(kSomeSource, base::FilePath(kMountDir), {}, &error);
  EXPECT_TRUE(mount_point);
  EXPECT_EQ(MountError::kSuccess, error);

  // If an Unmount fails, we should be able to retry.
  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kUnknownError));
  EXPECT_EQ(MountError::kUnknownError, mount_point->Unmount());

  EXPECT_CALL(platform_, Unmount(base::FilePath(kMountDir), "fuseblk.fusefs"))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_CALL(platform_, RemoveEmptyDirectory(kMountDir))
      .WillOnce(Return(true));
  EXPECT_EQ(MountError::kSuccess, mount_point->Unmount());
}

}  // namespace cros_disks
