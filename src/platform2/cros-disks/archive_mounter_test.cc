// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/archive_mounter.h"

#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/strings/string_split.h>
#include <brillo/process/process_reaper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::Contains;
using testing::ElementsAre;
using testing::Return;
using testing::UnorderedElementsAre;

const char kArchiveType[] = "archive";
const char kSomeSource[] = "/home/user/something.archive";
const char kMountDir[] = "/mnt";
const int kPasswordNeededCode = 42;

// Mock Platform implementation for testing.
class MockFUSEPlatform : public Platform {
 public:
  MOCK_METHOD(bool, PathExists, (const std::string&), (const, override));
};

class FakeSandboxedProcessFactory : public SandboxedProcessFactory {
 public:
  std::unique_ptr<SandboxedProcess> CreateSandboxedProcess() const override {
    auto process = std::make_unique<FakeSandboxedProcess>();
    process->NewPidNamespace();
    return process;
  }
};

}  // namespace

class ArchiveMounterTest : public ::testing::Test {
 public:
  ArchiveMounterTest() {
    ON_CALL(platform_, PathExists).WillByDefault(Return(true));
  }

 protected:
  static constexpr char kFileSystemType[] = "archivefs";

  std::unique_ptr<ArchiveMounter> CreateMounter(
      std::vector<int> password_needed_codes) {
    return std::make_unique<ArchiveMounter>(
        &platform_, &process_reaper_, kFileSystemType, kArchiveType, &metrics_,
        "ArchiveMetrics", std::move(password_needed_codes),
        std::make_unique<FakeSandboxedProcessFactory>());
  }

  std::unique_ptr<FakeSandboxedProcess> PrepareSandbox(
      const ArchiveMounter& mounter,
      const std::string& source,
      std::vector<std::string> params,
      MountError* error) const {
    auto sandbox = mounter.PrepareSandbox(source, base::FilePath(kMountDir),
                                          std::move(params), error);
    return std::unique_ptr<FakeSandboxedProcess>(
        static_cast<FakeSandboxedProcess*>(sandbox.release()));
  }

  MockFUSEPlatform platform_;
  brillo::ProcessReaper process_reaper_;
  Metrics metrics_;
};

TEST_F(ArchiveMounterTest, FileSystemType) {
  const auto mounter = CreateMounter({});
  EXPECT_EQ(mounter->filesystem_type(), kFileSystemType);
}

TEST_F(ArchiveMounterTest, CanMount) {
  auto mounter = CreateMounter({});
  base::FilePath name;
  EXPECT_TRUE(mounter->CanMount("/foo/bar/baz.archive", {}, &name));
  EXPECT_EQ("baz.archive", name.value());
  EXPECT_FALSE(mounter->CanMount("/foo/bar/baz.something", {}, &name));
  EXPECT_FALSE(mounter->CanMount("baz.archive", {}, &name));
  EXPECT_FALSE(mounter->CanMount(".archive", {}, &name));
  EXPECT_FALSE(mounter->CanMount("", {}, &name));
}

TEST_F(ArchiveMounterTest, InvalidPathsRejected) {
  auto mounter = CreateMounter({});
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, "foo.archive", {}, &error);
    EXPECT_NE(MountError::kSuccess, error);
    EXPECT_FALSE(sandbox);
  }
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, "/foo/../etc/foo.archive", {}, &error);
    EXPECT_NE(MountError::kSuccess, error);
    EXPECT_FALSE(sandbox);
  }
}

TEST_F(ArchiveMounterTest, AppArgs) {
  auto mounter = CreateMounter({});
  MountError error = MountError::kUnknownError;
  const std::unique_ptr<FakeSandboxedProcess> sandbox =
      PrepareSandbox(*mounter, kSomeSource, {}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  ASSERT_TRUE(sandbox);
  EXPECT_THAT(sandbox->arguments(), ElementsAre("-o", _, kSomeSource));
  std::vector<std::string> opts =
      base::SplitString(sandbox->arguments()[1], ",", base::KEEP_WHITESPACE,
                        base::SPLIT_WANT_ALL);
  EXPECT_THAT(opts,
              UnorderedElementsAre("umask=0222", "uid=1000", "gid=1001", "ro"));
}

TEST_F(ArchiveMounterTest, SimulateProgressForTesting) {
  auto mounter = CreateMounter({});
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, kSomeSource, {}, &error);
    EXPECT_EQ(MountError::kSuccess, error);
    ASSERT_TRUE(sandbox);
    EXPECT_FALSE(sandbox->GetSimulateProgressForTesting());
  }
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, "/home/user/b1238564_.zip", {}, &error);
    EXPECT_EQ(MountError::kSuccess, error);
    ASSERT_TRUE(sandbox);
    EXPECT_FALSE(sandbox->GetSimulateProgressForTesting());
  }
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, "/home/user/b1238564", {}, &error);
    EXPECT_EQ(MountError::kSuccess, error);
    ASSERT_TRUE(sandbox);
    EXPECT_FALSE(sandbox->GetSimulateProgressForTesting());
  }
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, "/home/user/b1238564.zip", {}, &error);
    EXPECT_EQ(MountError::kSuccess, error);
    ASSERT_TRUE(sandbox);
    EXPECT_TRUE(sandbox->GetSimulateProgressForTesting());
  }
  {
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox = PrepareSandbox(
        *mounter, "/home/user/b1238564.something.zip", {}, &error);
    EXPECT_EQ(MountError::kSuccess, error);
    ASSERT_TRUE(sandbox);
    EXPECT_TRUE(sandbox->GetSimulateProgressForTesting());
  }
}

TEST_F(ArchiveMounterTest, FileNotFound) {
  EXPECT_CALL(platform_, PathExists(kSomeSource)).WillRepeatedly(Return(false));
  auto mounter = CreateMounter({});
  MountError error = MountError::kUnknownError;
  const std::unique_ptr<FakeSandboxedProcess> sandbox =
      PrepareSandbox(*mounter, kSomeSource, {}, &error);
  EXPECT_NE(MountError::kSuccess, error);
  EXPECT_FALSE(sandbox);
}

TEST_F(ArchiveMounterTest, WithPassword) {
  const std::string password = "My Password";

  auto mounter = CreateMounter({kPasswordNeededCode});
  MountError error = MountError::kUnknownError;
  const std::unique_ptr<FakeSandboxedProcess> sandbox =
      PrepareSandbox(*mounter, kSomeSource, {"password=" + password}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  ASSERT_TRUE(sandbox);
  EXPECT_EQ(password, sandbox->input());
  // Make sure password is not in args.
  std::vector<std::string> opts =
      base::SplitString(sandbox->arguments()[1], ",", base::KEEP_WHITESPACE,
                        base::SPLIT_WANT_ALL);
  EXPECT_THAT(opts,
              UnorderedElementsAre("umask=0222", "uid=1000", "gid=1001", "ro"));
}

TEST_F(ArchiveMounterTest, NoPassword) {
  auto mounter = CreateMounter({kPasswordNeededCode});
  MountError error = MountError::kUnknownError;
  const std::unique_ptr<FakeSandboxedProcess> sandbox =
      PrepareSandbox(*mounter, kSomeSource,
                     {
                         "Password=1",   // Options are case sensitive
                         "password =2",  // Space is significant
                         " password=3",  // Space is significant
                         "password",     // Not a valid option
                     },
                     &error);
  ASSERT_TRUE(sandbox);
  EXPECT_EQ("", sandbox->input());
}

TEST_F(ArchiveMounterTest, CopiesPassword) {
  for (const std::string password : {
           "",
           " ",
           "=",
           "simple",
           R"( !@#$%^&*()_-+={[}]|\:;"'<,>.?/ )",
       }) {
    auto mounter = CreateMounter({kPasswordNeededCode});
    MountError error = MountError::kUnknownError;
    const std::unique_ptr<FakeSandboxedProcess> sandbox =
        PrepareSandbox(*mounter, kSomeSource, {"password=" + password}, &error);
    ASSERT_TRUE(sandbox);
    EXPECT_EQ(password, sandbox->input());
  }
}

TEST_F(ArchiveMounterTest, IgnoredIfNotNeeded) {
  auto mounter = CreateMounter({});
  MountError error = MountError::kUnknownError;
  auto sandbox =
      PrepareSandbox(*mounter, kSomeSource, {"password=foo"}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  ASSERT_TRUE(sandbox);
  EXPECT_EQ("", sandbox->input());
}

TEST_F(ArchiveMounterTest, IsValidEncoding) {
  EXPECT_FALSE(ArchiveMounter::IsValidEncoding(""));
  EXPECT_FALSE(ArchiveMounter::IsValidEncoding("a,b"));
  EXPECT_TRUE(ArchiveMounter::IsValidEncoding("UTF-8"));
  EXPECT_TRUE(ArchiveMounter::IsValidEncoding("SJIS"));
  EXPECT_TRUE(ArchiveMounter::IsValidEncoding("Shift_JIS"));
  EXPECT_TRUE(ArchiveMounter::IsValidEncoding("ANSI_X3.4-1986"));
  EXPECT_TRUE(ArchiveMounter::IsValidEncoding("ISO_646.IRV:1991"));
  EXPECT_TRUE(ArchiveMounter::IsValidEncoding("a.z_A:Z-09"));
}

// Tests that the 'encoding' option is passed to the FUSE mounter.
TEST_F(ArchiveMounterTest, EncodingOption) {
  const std::string encoding = "MyEncoding";

  const std::unique_ptr<ArchiveMounter> mounter = CreateMounter({});
  MountError error = MountError::kUnknownError;
  const std::unique_ptr<FakeSandboxedProcess> sandbox = PrepareSandbox(
      *mounter, kSomeSource,
      {"option1=dummy", "encoding=" + encoding, "option2=dummy2"}, &error);
  EXPECT_EQ(MountError::kSuccess, error);
  ASSERT_TRUE(sandbox);
  EXPECT_THAT(sandbox->arguments(), Contains("encoding=" + encoding));
}

// Tests that the 'encoding' option is rejected if it contains invalid
// characters (crbug.com/1398994).
TEST_F(ArchiveMounterTest, FailOnInvalidEncoding) {
  const std::unique_ptr<ArchiveMounter> mounter = CreateMounter({});
  MountError error = MountError::kUnknownError;
  const std::unique_ptr<FakeSandboxedProcess> sandbox = PrepareSandbox(
      *mounter, kSomeSource, {"encoding=ascii,fsname=exploit"}, &error);
  EXPECT_EQ(MountError::kInvalidArgument, error);
  EXPECT_FALSE(sandbox);
}

}  // namespace cros_disks
