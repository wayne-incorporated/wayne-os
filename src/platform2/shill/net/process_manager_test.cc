// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/process_manager.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/rand_util.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <brillo/minijail/mock_minijail.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::StrEq;
using testing::WithArgs;

namespace shill {

class ProcessManagerTest : public testing::Test {
 public:
  ProcessManagerTest() : process_manager_(ProcessManager::GetInstance()) {}

  void SetUp() override { process_manager_->minijail_ = &minijail_; }

  void TearDown() override {
    process_manager_->watched_processes_.clear();
    process_manager_->pending_termination_processes_.clear();
  }

  void AddWatchedProcess(pid_t pid, ProcessManager::ExitCallback callback) {
    process_manager_->watched_processes_[pid].exit_callback =
        std::move(callback);
  }

  void AddTerminateProcess(
      pid_t pid, std::unique_ptr<base::CancelableOnceClosure> timeout_handler) {
    process_manager_->pending_termination_processes_[pid] =
        std::move(timeout_handler);
  }

  void AssertEmptyWatchedProcesses() {
    EXPECT_TRUE(process_manager_->watched_processes_.empty());
  }

  void AssertNonEmptyWatchedProcesses() {
    EXPECT_FALSE(process_manager_->watched_processes_.empty());
  }

  void AssertEmptyTerminateProcesses() {
    EXPECT_TRUE(process_manager_->pending_termination_processes_.empty());
  }

  void OnProcessExited(pid_t pid, int exit_status) {
    siginfo_t info;
    info.si_status = exit_status;
    process_manager_->OnProcessExited(pid, info);
  }

  void OnTerminationTimeout(pid_t pid, bool kill_signal) {
    process_manager_->ProcessTerminationTimeoutHandler(pid, kill_signal);
  }

  void RunUntilIdle() { task_environment_.RunUntilIdle(); }

 protected:
  class CallbackObserver {
   public:
    CallbackObserver()
        : exited_callback_(base::BindOnce(&CallbackObserver::OnProcessExited,
                                          base::Unretained(this))),
          termination_timeout_callback_(
              base::BindOnce(&CallbackObserver::OnTerminationTimeout,
                             base::Unretained(this))) {}
    virtual ~CallbackObserver() = default;

    MOCK_METHOD(void, OnProcessExited, (int));
    MOCK_METHOD(void, OnTerminationTimeout, ());

    ProcessManager::ExitCallback exited_callback_;
    base::OnceClosure termination_timeout_callback_;
  };

  // Should be the first member to be initialized first and destroyed last.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};

  brillo::MockMinijail minijail_;
  ProcessManager* process_manager_;
};

MATCHER_P2(IsProcessArgs, program, args, "") {
  if (std::string(arg[0]) != program) {
    return false;
  }
  int index = 1;
  for (const auto& option : args) {
    if (std::string(arg[index++]) != option) {
      return false;
    }
  }
  return arg[index] == nullptr;
}

MATCHER_P(IsProcessEnv, env, "") {
  std::map<std::string, std::string> actual;
  for (size_t i = 0; i < arg.size() - 1; ++i) {
    char* str = arg[i];
    char* eq = strchr(str, '=');
    if (!eq) {
      return false;
    }

    if (!actual
             .insert(std::make_pair(std::string(str, eq), std::string(eq + 1)))
             .second) {
      return false;
    }
  }
  return env == actual && arg.back() == nullptr;
}

TEST_F(ProcessManagerTest, WatchedProcessExited) {
  const pid_t kPid = 123;
  const int kExitStatus = 1;
  CallbackObserver observer;
  AddWatchedProcess(kPid, std::move(observer.exited_callback_));

  EXPECT_CALL(observer, OnProcessExited(kExitStatus)).Times(1);
  OnProcessExited(kPid, kExitStatus);
  AssertEmptyWatchedProcesses();
}

TEST_F(ProcessManagerTest, TerminateProcessExited) {
  const pid_t kPid = 123;
  CallbackObserver observer;
  auto timeout_handler = std::make_unique<base::CancelableOnceClosure>(
      std::move(observer.termination_timeout_callback_));
  AddTerminateProcess(kPid, std::move(timeout_handler));

  EXPECT_CALL(observer, OnTerminationTimeout()).Times(0);
  OnProcessExited(kPid, 1);
  AssertEmptyTerminateProcesses();
}

TEST_F(ProcessManagerTest,
       StartProcessInMinijailWithPipesReturnsPidAndWatchesChild) {
  const std::string kProgram = "/usr/bin/dump";
  const std::vector<std::string> kArgs = {"-b", "-g"};
  const std::map<std::string, std::string> kEnv = {
      {"one", "1"},
      {"two", "2"},
  };
  const std::string kUser = "user";
  const std::string kGroup = "group";
  const uint64_t kCapMask = 1;
  const pid_t kPid = 123;
  int stdin_fd;
  int stdout_fd;
  int stderr_fd;

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = kUser;
  minijail_options.group = kGroup;
  minijail_options.capmask = kCapMask;
  minijail_options.inherit_supplementary_groups = false;

  EXPECT_CALL(minijail_, DropRoot(_, StrEq(kUser), StrEq(kGroup)))
      .WillOnce(Return(true));
  EXPECT_CALL(minijail_, UseCapabilities(_, kCapMask)).Times(1);
  EXPECT_CALL(minijail_, ResetSignalMask(_)).Times(1);
  EXPECT_CALL(minijail_, CloseOpenFds(_)).Times(1);
  EXPECT_CALL(minijail_, PreserveFd(_, _, _)).Times(3);
  EXPECT_CALL(
      minijail_,
      RunEnvPipesAndDestroy(_,  // minijail*
                            IsProcessArgs(kProgram, kArgs), IsProcessEnv(kEnv),
                            _,  // pid_t*
                            &stdin_fd, &stdout_fd, &stderr_fd))
      .WillOnce(DoAll(SetArgPointee<3>(kPid), Return(true)));

  struct std_file_descriptors std_fds {
    &stdin_fd, &stdout_fd, &stderr_fd
  };
  pid_t actual_pid = process_manager_->StartProcessInMinijailWithPipes(
      FROM_HERE, base::FilePath(kProgram), kArgs, kEnv, minijail_options,
      base::DoNothing(), std_fds);
  EXPECT_EQ(kPid, actual_pid);
  AssertNonEmptyWatchedProcesses();
}

TEST_F(ProcessManagerTest,
       StartProcessInMinijailWithPipesHandlesFailureOfDropRoot) {
  const std::string kProgram = "/usr/bin/dump";
  const std::vector<std::string> kArgs = {"-b", "-g"};
  const std::map<std::string, std::string> kEnv = {
      {"one", "1"},
      {"two", "2"},
  };
  const std::string kUser = "user";
  const std::string kGroup = "group";
  const uint64_t kCapMask = 1;

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = kUser;
  minijail_options.group = kGroup;
  minijail_options.capmask = kCapMask;
  minijail_options.inherit_supplementary_groups = false;

  EXPECT_CALL(minijail_, DropRoot(_, StrEq(kUser), StrEq(kGroup)))
      .WillOnce(Return(false));
  EXPECT_CALL(minijail_,
              RunEnvPipesAndDestroy(_, IsProcessArgs(kProgram, kArgs),
                                    IsProcessEnv(kEnv), _, _, _, _))
      .Times(0);

  struct std_file_descriptors std_fds = {nullptr, nullptr, nullptr};
  pid_t actual_pid = process_manager_->StartProcessInMinijailWithPipes(
      FROM_HERE, base::FilePath(kProgram), kArgs, {}, minijail_options,
      base::DoNothing(), std_fds);
  EXPECT_EQ(-1, actual_pid);
  AssertEmptyWatchedProcesses();
}

TEST_F(ProcessManagerTest,
       StartProcessInMinijailWithPipesHandlesFailureOfRunAndDestroy) {
  const std::string kProgram = "/usr/bin/dump";
  const std::vector<std::string> kArgs = {"-b", "-g"};
  const std::map<std::string, std::string> kEnv = {
      {"one", "1"},
      {"two", "2"},
  };
  const std::string kUser = "user";
  const std::string kGroup = "group";
  const uint64_t kCapMask = 1;

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = kUser;
  minijail_options.group = kGroup;
  minijail_options.capmask = kCapMask;
  minijail_options.inherit_supplementary_groups = false;

  EXPECT_CALL(minijail_, DropRoot(_, StrEq(kUser), StrEq(kGroup)))
      .WillOnce(Return(true));
  EXPECT_CALL(minijail_, UseCapabilities(_, kCapMask)).Times(1);
  EXPECT_CALL(minijail_,
              RunEnvPipesAndDestroy(_, IsProcessArgs(kProgram, kArgs),
                                    IsProcessEnv(kEnv), _, _, _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(minijail_, CloseOpenFds(_)).Times(1);
  EXPECT_CALL(minijail_, PreserveFd(_, _, _)).Times(3);

  struct std_file_descriptors std_fds = {nullptr, nullptr, nullptr};
  pid_t actual_pid = process_manager_->StartProcessInMinijailWithPipes(
      FROM_HERE, base::FilePath(kProgram), kArgs, kEnv, minijail_options,
      base::DoNothing(), std_fds);
  EXPECT_EQ(-1, actual_pid);
  AssertEmptyWatchedProcesses();
}

TEST_F(ProcessManagerTest, UpdateExitCallbackUpdatesCallback) {
  const pid_t kPid = 123;
  const int kExitStatus = 1;
  CallbackObserver original_observer;
  AddWatchedProcess(kPid, std::move(original_observer.exited_callback_));

  CallbackObserver new_observer;
  EXPECT_CALL(original_observer, OnProcessExited(_)).Times(0);
  EXPECT_TRUE(process_manager_->UpdateExitCallback(
      kPid, std::move(new_observer.exited_callback_)));
  EXPECT_CALL(new_observer, OnProcessExited(_)).Times(1);
  OnProcessExited(kPid, kExitStatus);
}

TEST_F(ProcessManagerTest, StartProcessWithMinijailWithStdout) {
  const pid_t kPid = 456;
  const std::string kProgram = "/usr/bin/dump";
  const std::vector<std::string> kArgs = {"-b", "-g"};
  const std::map<std::string, std::string> kEnv = {
      {"one", "1"},
      {"two", "2"},
  };
  const std::string kUser = "user";
  const std::string kGroup = "group";
  constexpr uint64_t kCapMask = 1;

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = kUser;
  minijail_options.group = kGroup;
  minijail_options.capmask = kCapMask;
  minijail_options.inherit_supplementary_groups = false;

  std::optional<int> actual_exit_status;
  std::string actual_stdout_str;
  auto callback = [&actual_exit_status, &actual_stdout_str](
                      int exit_status, const std::string& stdout_str) {
    actual_exit_status = exit_status;
    actual_stdout_str = stdout_str;
  };

  base::ScopedFD process_side_stdout_fd;

  EXPECT_CALL(minijail_, DropRoot(_, StrEq(kUser), StrEq(kGroup)))
      .WillOnce(Return(true));
  EXPECT_CALL(minijail_, UseCapabilities(_, kCapMask)).Times(1);
  EXPECT_CALL(minijail_,
              RunEnvPipesAndDestroy(_, IsProcessArgs(kProgram, kArgs),
                                    IsProcessEnv(kEnv), _, _, _, _))
      .WillOnce(
          WithArgs<3, 5>([&process_side_stdout_fd](pid_t* pid, int* stdout_fd) {
            int fds[2];
            CHECK(base::CreateLocalNonBlockingPipe(fds));
            *stdout_fd = fds[0];
            process_side_stdout_fd.reset(fds[1]);
            *pid = kPid;
            return true;
          }));
  EXPECT_CALL(minijail_, CloseOpenFds(_)).Times(1);
  EXPECT_CALL(minijail_, PreserveFd(_, _, _)).Times(3);

  pid_t actual_pid = process_manager_->StartProcessInMinijailWithStdout(
      FROM_HERE, base::FilePath(kProgram), kArgs, kEnv, minijail_options,
      base::BindLambdaForTesting(callback));
  ASSERT_NE(actual_pid, ProcessManager::kInvalidPID);

  constexpr int kExpectedExitStatus = 123;
  std::string expected_stdout;
  // Writes a random string to the pipe, appends it to |expected_stdout|, and
  // forward the dispatcher.
  const auto write_to_pipe = [&process_side_stdout_fd, &expected_stdout,
                              this]() {
    const char c = static_cast<char>(base::RandInt('a', 'z'));
    const int length = base::RandInt(0, 2048);
    const std::string str = std::string(length, c);
    CHECK(base::WriteFileDescriptor(process_side_stdout_fd.get(), str));
    expected_stdout.append(str);
    RunUntilIdle();
  };

  write_to_pipe();
  EXPECT_FALSE(actual_exit_status.has_value());

  write_to_pipe();
  EXPECT_FALSE(actual_exit_status.has_value());

  OnProcessExited(actual_pid, kExpectedExitStatus);
  EXPECT_FALSE(actual_exit_status.has_value());

  write_to_pipe();
  process_side_stdout_fd.reset();
  RunUntilIdle();

  EXPECT_TRUE(actual_exit_status.has_value());
  EXPECT_EQ(actual_exit_status.value(), kExpectedExitStatus);
  EXPECT_EQ(actual_stdout_str, expected_stdout);

  AssertEmptyWatchedProcesses();
}

TEST_F(ProcessManagerTest, StartProcessWithMinijailWithPreservedNonstdFds) {
  const std::string kProgram = "/usr/bin/dump";
  const std::vector<std::string> kArgs = {"-b", "-g"};
  const std::map<std::string, std::string> kEnv = {
      {"one", "1"},
      {"two", "2"},
  };
  const std::string kUser = "user";
  const std::string kGroup = "group";
  const uint64_t kCapMask = 1;
  const pid_t kPid = 789;
  int preserved_nonstd_fd = 5;
  int stdin_fd;
  int stdout_fd;
  int stderr_fd;

  ProcessManager::MinijailOptions minijail_options;
  minijail_options.user = kUser;
  minijail_options.group = kGroup;
  minijail_options.capmask = kCapMask;
  minijail_options.inherit_supplementary_groups = false;
  minijail_options.preserved_nonstd_fds.insert(preserved_nonstd_fd);

  EXPECT_CALL(minijail_, DropRoot(_, StrEq(kUser), StrEq(kGroup)))
      .WillOnce(Return(true));
  EXPECT_CALL(minijail_, UseCapabilities(_, kCapMask)).Times(1);
  EXPECT_CALL(minijail_, ResetSignalMask(_)).Times(1);
  EXPECT_CALL(minijail_, CloseOpenFds(_)).Times(1);
  EXPECT_CALL(minijail_, PreserveFd(_, _, _)).Times(3);
  EXPECT_CALL(minijail_,
              PreserveFd(_, preserved_nonstd_fd, preserved_nonstd_fd))
      .Times(1);
  EXPECT_CALL(
      minijail_,
      RunEnvPipesAndDestroy(_,  // minijail*
                            IsProcessArgs(kProgram, kArgs), IsProcessEnv(kEnv),
                            _,  // pid_t*
                            &stdin_fd, &stdout_fd, &stderr_fd))
      .WillOnce(DoAll(SetArgPointee<3>(kPid), Return(true)));

  struct std_file_descriptors std_fds {
    &stdin_fd, &stdout_fd, &stderr_fd
  };
  pid_t actual_pid = process_manager_->StartProcessInMinijailWithPipes(
      FROM_HERE, base::FilePath(kProgram), kArgs, kEnv, minijail_options,
      base::DoNothing(), std_fds);
  EXPECT_EQ(kPid, actual_pid);
  AssertNonEmptyWatchedProcesses();
}

}  // namespace shill
