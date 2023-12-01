// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <set>
#include <string>
#include <vector>

#include <base/strings/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/executor/utils/sandboxed_process.h"

namespace diagnostics {
namespace {

using ::testing::_;
using ::testing::Contains;
using ::testing::Invoke;
using ::testing::Not;
using ::testing::Return;

class MockSandboxedProcess : public SandboxedProcess {
 public:
  using SandboxedProcess::SandboxedProcess;

  MOCK_METHOD(void, BrilloProcessAddArg, (const std::string&), (override));
  MOCK_METHOD(bool, BrilloProcessStart, (), (override));
  MOCK_METHOD(bool, IsPathExists, (const base::FilePath&), (const override));
};

constexpr char kTestSeccompName[] = "test_seccomp.policy";
constexpr char kTestUser[] = "foo_user";
constexpr uint64_t kTestCapabilitiesMask = 0xa42;
constexpr char kTestCapabilitiesMaskHex[] = "0xa42";
constexpr char kTestReadOnlyFile[] = "/some/readonly/file";
constexpr char kTestReadOnlyFileNotExist[] = "/some/not/exist/readonly/file";
constexpr char kTestWritableFile[] = "/some/writable/file";
constexpr char kTestWritableFileMountFlag[] =
    "/some/writable/file,/some/writable/file,1";

class SandboxedProcessTest : public testing::Test {
 protected:
  SandboxedProcessTest() = default;
  SandboxedProcessTest(const SandboxedProcessTest&) = delete;
  SandboxedProcessTest& operator=(const SandboxedProcessTest&) = delete;

  // Sets up the expect calls needed to correctly get minijail arguments and
  // commands.
  void SetUpExpectCallForMinijailParsing(MockSandboxedProcess& process) {
    has_minijail_bin_ = false;
    has_minijail_finish_flag_ = false;
    minijail_args_set_ = std::set<std::vector<std::string>>{};
    minijail_args_ = std::vector<std::string>{};
    cmd_ = std::vector<std::string>{};
    EXPECT_CALL(process, BrilloProcessStart()).WillOnce(Return(true));
    EXPECT_CALL(process, IsPathExists(base::FilePath{kTestReadOnlyFile}))
        .WillOnce(Return(true));
    EXPECT_CALL(process,
                IsPathExists(base::FilePath{kTestReadOnlyFileNotExist}))
        .WillOnce(Return(false));
    EXPECT_CALL(process, BrilloProcessAddArg(_))
        .WillRepeatedly(Invoke([&](const std::string& arg) {
          // These are minijail flags with string argument.
          const std::set<std::string> kMinijailStringArgFlags{
              "-u", "-g", "-c", "-S", "-b", "-P", "-k"};
          if (!has_minijail_bin_) {
            EXPECT_EQ(arg, kMinijailBinary);
            has_minijail_bin_ = true;
            return;
          }
          if (!has_minijail_finish_flag_) {
            if (arg == "--") {
              has_minijail_finish_flag_ = true;
              return;
            }
            minijail_args_.push_back(arg);
            if (!kMinijailStringArgFlags.count(minijail_args_[0]) ||
                minijail_args_.size() == 2) {
              auto [unused, success] =
                  minijail_args_set_.insert(minijail_args_);
              EXPECT_TRUE(success) << "Duplicated argument: "
                                   << base::JoinString(minijail_args_, " ");
              minijail_args_.clear();
            }
            return;
          }
          cmd_.push_back(arg);
        }));
  }

 protected:
  std::set<std::vector<std::string>> minijail_args_set_;
  std::vector<std::string> cmd_;

 private:
  bool has_minijail_bin_;
  bool has_minijail_finish_flag_;
  std::vector<std::string> minijail_args_;
};

TEST_F(SandboxedProcessTest, Default) {
  std::vector<std::string> expected_cmd{"ls", "-al"};
  MockSandboxedProcess process{
      /*command=*/expected_cmd,
      /*seccomp_filename=*/kTestSeccompName,
      SandboxedProcess::Options{
          .user = kTestUser,
          .capabilities_mask = kTestCapabilitiesMask,
          .readonly_mount_points = {base::FilePath{kTestReadOnlyFile},
                                    base::FilePath{kTestReadOnlyFileNotExist}},
          .writable_mount_points = {base::FilePath{kTestWritableFile}},
      }};

  SetUpExpectCallForMinijailParsing(process);

  EXPECT_TRUE(process.Start());
  EXPECT_EQ(cmd_, expected_cmd);
  EXPECT_EQ(minijail_args_set_,
            (std::set<std::vector<std::string>>{
                {"-P", "/mnt/empty"},
                {"-v"},
                {"-Kslave"},
                {"-r"},
                {"-l"},
                {"-e"},
                {"--uts"},
                {"-u", kTestUser},
                {"-g", kTestUser},
                {"-G"},
                {"-c", kTestCapabilitiesMaskHex},
                {"-S", base::FilePath{kSeccompPolicyDirectory}
                           .Append(kTestSeccompName)
                           .value()},
                {"-n"},
                {"-b", kTestReadOnlyFile},
                {"-b", kTestWritableFileMountFlag},
                {"-b", "/"},
                {"-b", "/dev/log"},
                {"-d"},
                {"-k", "tmpfs,/tmp,tmpfs"},
                {"-k", "tmpfs,/proc,tmpfs"},
                {"-k", "tmpfs,/run,tmpfs"},
                {"-k", "tmpfs,/sys,tmpfs"},
                {"-k", "tmpfs,/var,tmpfs"},
            }));
}

TEST_F(SandboxedProcessTest, NoNetworkNamespace) {
  std::vector<std::string> expected_cmd{"ls", "-al"};
  MockSandboxedProcess process{
      /*command=*/expected_cmd,
      /*seccomp_filename=*/kTestSeccompName,
      SandboxedProcess::Options{
          .user = kTestUser,
          .capabilities_mask = kTestCapabilitiesMask,
          .readonly_mount_points = {base::FilePath{kTestReadOnlyFile},
                                    base::FilePath{kTestReadOnlyFileNotExist}},
          .writable_mount_points = {base::FilePath{kTestWritableFile}},
          .sandbox_option = NO_ENTER_NETWORK_NAMESPACE,
      }};

  SetUpExpectCallForMinijailParsing(process);

  EXPECT_TRUE(process.Start());
  EXPECT_EQ(cmd_, expected_cmd);
  EXPECT_THAT(minijail_args_set_,
              Not(Contains(std::vector<std::string>{"-e"})));
}

TEST_F(SandboxedProcessTest, MOUNT_DLC) {
  std::vector<std::string> expected_cmd{"ls", "-al"};
  MockSandboxedProcess process{
      /*command=*/expected_cmd,
      /*seccomp_filename=*/kTestSeccompName,
      SandboxedProcess::Options{
          .user = kTestUser,
          .capabilities_mask = kTestCapabilitiesMask,
          .readonly_mount_points = {base::FilePath{kTestReadOnlyFile},
                                    base::FilePath{kTestReadOnlyFileNotExist}},
          .writable_mount_points = {base::FilePath{kTestWritableFile}},
          .sandbox_option = MOUNT_DLC,
      }};

  SetUpExpectCallForMinijailParsing(process);

  EXPECT_TRUE(process.Start());
  EXPECT_EQ(cmd_, expected_cmd);
  EXPECT_THAT(
      minijail_args_set_,
      Contains(std::vector<std::string>{
          "-k", "/run/imageloader,/run/imageloader,none,MS_BIND|MS_REC"}));
}

}  // namespace
}  // namespace diagnostics
