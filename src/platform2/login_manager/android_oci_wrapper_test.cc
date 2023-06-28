// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/android_oci_wrapper.h"

#include <memory>
#include <string>
#include <vector>

#include <base/bind.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "login_manager/mock_system_utils.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Ge;
using ::testing::Invoke;
using ::testing::Le;
using ::testing::Ne;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace login_manager {

namespace {

class AndroidOciWrapperTest : public ::testing::Test {
 public:
  AndroidOciWrapperTest() = default;
  AndroidOciWrapperTest(const AndroidOciWrapperTest&) = delete;
  AndroidOciWrapperTest& operator=(const AndroidOciWrapperTest&) = delete;

  ~AndroidOciWrapperTest() override = default;

  void SetUp() override {
    containers_directory_ = std::make_unique<base::ScopedTempDir>();
    ASSERT_TRUE(containers_directory_->CreateUniqueTempDir());

    impl_ = std::make_unique<AndroidOciWrapper>(
        &system_utils_, containers_directory_->GetPath());
  }

 protected:
  void StartContainerAsParent() {
    run_oci_pid_ = 9063;
    container_pid_ = 9064;

    EXPECT_CALL(system_utils_, fork()).WillOnce(Return(run_oci_pid_));

    EXPECT_CALL(system_utils_, Wait(run_oci_pid_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(0), Return(run_oci_pid_)));

    base::FilePath run_path =
        base::FilePath(ContainerManagerInterface::kContainerRunPath)
            .Append(AndroidOciWrapper::kContainerId)
            .Append(AndroidOciWrapper::kContainerPidName);
    std::string container_pid_str = base::NumberToString(container_pid_) + "\n";
    EXPECT_CALL(system_utils_, ReadFileToString(run_path, _))
        .WillOnce(DoAll(SetArgPointee<1>(container_pid_str), Return(true)));

    ASSERT_TRUE(CallStartContainer());
  }

  bool CallStartContainer() {
    return impl_->StartContainer(
        std::vector<std::string>{},
        base::Bind(&AndroidOciWrapperTest::ExitCallback,
                   base::Unretained(this)));
  }

  void ExpectKill(bool forceful, int exit_code) {
    std::vector<std::string> argv;
    argv.push_back(AndroidOciWrapper::kRunOciPath);
    argv.push_back(AndroidOciWrapper::kRunOciLogging);
    if (forceful)
      argv.push_back(AndroidOciWrapper::kRunOciKillSignal);
    argv.push_back(AndroidOciWrapper::kRunOciKillCommand);
    argv.push_back(AndroidOciWrapper::kContainerId);
    EXPECT_CALL(system_utils_, LaunchAndWait(argv, _))
        .WillOnce(DoAll(SetArgPointee<1>(exit_code), Return(true)));
  }

  void ExpectDestroy(int exit_code) {
    const std::vector<std::string> argv = {
        AndroidOciWrapper::kRunOciPath, AndroidOciWrapper::kRunOciLogging,
        AndroidOciWrapper::kRunOciConfigPath,
        AndroidOciWrapper::kRunOciDestroyCommand,
        AndroidOciWrapper::kContainerId};
    EXPECT_CALL(system_utils_, LaunchAndWait(argv, _))
        .WillOnce(DoAll(SetArgPointee<1>(exit_code), Return(true)));
  }

  void ExitCallback(pid_t pid, ArcContainerStopReason reason) {
    ASSERT_EQ(pid, container_pid_);

    callback_called_ = true;
    exit_reason_ = reason;
  }

  MockSystemUtils system_utils_;
  std::unique_ptr<base::ScopedTempDir> containers_directory_;

  std::unique_ptr<AndroidOciWrapper> impl_;

  pid_t run_oci_pid_ = 0;
  pid_t container_pid_ = 0;

  bool callback_called_ = false;
  ArcContainerStopReason exit_reason_ = ArcContainerStopReason::CRASH;
};

TEST_F(AndroidOciWrapperTest, KillOnLaunchTimeOut) {
  run_oci_pid_ = 9063;
  container_pid_ = 9064;

  EXPECT_CALL(system_utils_, fork()).WillOnce(Return(run_oci_pid_));

  EXPECT_CALL(system_utils_, Wait(run_oci_pid_, _, _)).WillOnce(Return(0));

  EXPECT_CALL(system_utils_, ProcessGroupIsGone(run_oci_pid_, _))
      .WillOnce(Return(false));
  EXPECT_CALL(system_utils_, kill(-run_oci_pid_, -1, SIGKILL))
      .WillOnce(Return(0));

  EXPECT_FALSE(CallStartContainer());
}

TEST_F(AndroidOciWrapperTest, GetContainerPID) {
  StartContainerAsParent();

  pid_t pid;
  ASSERT_TRUE(impl_->GetContainerPID(&pid));
  EXPECT_EQ(container_pid_, pid);
}

TEST_F(AndroidOciWrapperTest, CleanUpOnExit) {
  exit_reason_ = ArcContainerStopReason::USER_REQUEST;

  StartContainerAsParent();

  ExpectDestroy(0 /* exit_code */);

  siginfo_t status;
  status.si_pid = container_pid_;
  EXPECT_TRUE(impl_->HandleExit(status));

  EXPECT_TRUE(callback_called_);
  EXPECT_EQ(ArcContainerStopReason::CRASH, exit_reason_);
}

TEST_F(AndroidOciWrapperTest, ForcefulStatelessShutdownOnRequest) {
  StartContainerAsParent();

  ExpectKill(true /* forceful */, 0 /* exit_code */);

  impl_->RequestJobExit(ArcContainerStopReason::USER_REQUEST);
}

TEST_F(AndroidOciWrapperTest, GracefulStatefulShutdownOnRequest) {
  StartContainerAsParent();
  impl_->SetStatefulMode(StatefulMode::STATEFUL);

  ExpectKill(false /* forceful */, 0 /* exit_code */);

  impl_->RequestJobExit(ArcContainerStopReason::USER_REQUEST);
}

TEST_F(AndroidOciWrapperTest, ForcefulShutdownAfterGracefulShutdownFailed) {
  StartContainerAsParent();
  impl_->SetStatefulMode(StatefulMode::STATEFUL);

  ExpectKill(false /* forceful */, -1 /* exit_code */);
  ExpectKill(true /* forceful */, 0 /* exit_code */);

  impl_->RequestJobExit(ArcContainerStopReason::USER_REQUEST);
}

TEST_F(AndroidOciWrapperTest, KillJobOnEnsure) {
  StartContainerAsParent();

  base::TimeDelta delta = base::TimeDelta::FromSeconds(11);
  EXPECT_CALL(system_utils_, ProcessIsGone(container_pid_, delta))
      .WillOnce(Return(false));

  EXPECT_CALL(system_utils_, kill(container_pid_, _, SIGKILL))
      .WillOnce(Return(true));

  EXPECT_CALL(system_utils_, ProcessIsGone(container_pid_,
                                           Le(base::TimeDelta::FromSeconds(5))))
      .WillOnce(Return(true));

  ExpectDestroy(0 /* exit_code */);

  impl_->EnsureJobExit(delta);
}

TEST_F(AndroidOciWrapperTest, CleanExitAfterRequest) {
  StartContainerAsParent();

  ExpectKill(true /* forceful */, 0 /* exit_code */);

  impl_->RequestJobExit(ArcContainerStopReason::USER_REQUEST);

  base::TimeDelta delta = base::TimeDelta::FromSeconds(11);
  EXPECT_CALL(system_utils_, ProcessIsGone(container_pid_, delta))
      .WillOnce(Return(true));

  ExpectDestroy(0 /* exit_code */);

  impl_->EnsureJobExit(delta);

  EXPECT_TRUE(callback_called_);
  EXPECT_EQ(ArcContainerStopReason::USER_REQUEST, exit_reason_);
}

TEST_F(AndroidOciWrapperTest, StartContainerChildProcess) {
  EXPECT_CALL(system_utils_, fork()).WillOnce(Return(0));

  EXPECT_CALL(system_utils_,
              ChangeBlockedSignals(SIG_SETMASK, std::vector<int>()))
      .WillOnce(Return(true));

  base::FilePath container_absolute_path =
      containers_directory_->GetPath().Append("android");
  EXPECT_CALL(system_utils_, chdir(container_absolute_path))
      .WillOnce(Return(0));

  base::FilePath proc_fd_path(AndroidOciWrapper::kProcFdPath);
  std::vector<base::FilePath> fds = {
      proc_fd_path.Append("0"), proc_fd_path.Append("1"),
      proc_fd_path.Append("2"), proc_fd_path.Append("5"),
      proc_fd_path.Append("13")};
  EXPECT_CALL(system_utils_,
              EnumerateFiles(proc_fd_path, base::FileEnumerator::FILES, _))
      .WillOnce(DoAll(SetArgPointee<2>(fds), Return(true)));

  // It should never close stdin, stdout and stderr.
  EXPECT_CALL(system_utils_, close(0)).Times(0);
  EXPECT_CALL(system_utils_, close(1)).Times(0);
  EXPECT_CALL(system_utils_, close(2)).Times(0);
  EXPECT_CALL(system_utils_, close(5)).WillOnce(Return(0));
  EXPECT_CALL(system_utils_, close(13)).WillOnce(Return(0));

  EXPECT_CALL(system_utils_, setsid()).WillOnce(Return(0));
  EXPECT_CALL(system_utils_,
              WriteStringToFile(base::FilePath("/proc/self/oom_score_adj"), _))
      .WillOnce(Return(true));

  EXPECT_CALL(system_utils_,
              execve(base::FilePath(AndroidOciWrapper::kRunOciPath), _, _));

  CallStartContainer();
}

}  // namespace

}  // namespace login_manager
