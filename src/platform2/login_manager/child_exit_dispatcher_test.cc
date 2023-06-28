// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/child_exit_dispatcher.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <base/check_op.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/test/bind.h>
#include <brillo/asynchronous_signal_handler.h>
#include <brillo/message_loops/base_message_loop.h>
#include <gtest/gtest.h>

#include "login_manager/child_exit_handler.h"
#include "login_manager/system_utils_impl.h"

namespace login_manager {
namespace {

class ScopedSIGCHLDMask {
 public:
  ScopedSIGCHLDMask() {
    sigset_t signal_set;
    CHECK_EQ(sigemptyset(&signal_set), 0);
    CHECK_EQ(sigaddset(&signal_set, SIGCHLD), 0);
    CHECK_EQ(sigprocmask(SIG_BLOCK, &signal_set, &old_signal_set_), 0);
  }
  ~ScopedSIGCHLDMask() {
    CHECK_EQ(sigprocmask(SIG_SETMASK, &old_signal_set_, nullptr), 0);
  }

  ScopedSIGCHLDMask(const ScopedSIGCHLDMask&) = delete;
  ScopedSIGCHLDMask& operator=(const ScopedSIGCHLDMask&) = delete;

 private:
  sigset_t old_signal_set_;
};

// A fake child exit handler implementation for testing.
class FakeChildExitHandler : public ChildExitHandler {
 public:
  using HandleExitCallback = base::RepeatingCallback<bool(const siginfo_t&)>;

  explicit FakeChildExitHandler(const HandleExitCallback& callback)
      : callback_(callback) {}
  ~FakeChildExitHandler() override = default;

  FakeChildExitHandler(const FakeChildExitHandler&) = delete;
  FakeChildExitHandler& operator=(const FakeChildExitHandler&) = delete;

  // ChildExitHandler overrides.
  bool HandleExit(const siginfo_t& s) override { return callback_.Run(s); }

 private:
  HandleExitCallback callback_;
};

}  // namespace

class ChildExitDispatcherTest : public ::testing::Test {
 public:
  ChildExitDispatcherTest() = default;
  ChildExitDispatcherTest(const ChildExitDispatcherTest&) = delete;
  ChildExitDispatcherTest& operator=(const ChildExitDispatcherTest&) = delete;

  ~ChildExitDispatcherTest() override = default;

  void SetUp() override { brillo_loop_.SetAsCurrent(); }

 protected:
  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  brillo::BaseMessageLoop brillo_loop_{task_executor_.task_runner()};
  SystemUtilsImpl system_utils_;
  brillo::AsynchronousSignalHandler signal_handler_;
};

TEST_F(ChildExitDispatcherTest, ChildExit) {
  signal_handler_.Init();

  base::Optional<siginfo_t> siginfo;
  FakeChildExitHandler fake_handler(
      base::BindLambdaForTesting([&siginfo](const siginfo_t& s) {
        siginfo = s;
        brillo::MessageLoop::current()->BreakLoop();
        return true;
      }));
  auto dispatcher = std::make_unique<ChildExitDispatcher>(
      &signal_handler_, std::vector<ChildExitHandler*>{&fake_handler});

  // Fork off a child process that exits immediately.
  pid_t child_pid = system_utils_.fork();
  if (child_pid == 0) {
    _Exit(EXIT_SUCCESS);
  }

  // Spin the message loop.
  brillo_loop_.Run();

  // Verify child termination has been reported to |fake_handler|.
  ASSERT_TRUE(siginfo.has_value());
  EXPECT_EQ(child_pid, siginfo->si_pid);
  EXPECT_EQ(SIGCHLD, siginfo->si_signo);
  EXPECT_EQ(static_cast<int>(CLD_EXITED), siginfo->si_code);
  EXPECT_EQ(EXIT_SUCCESS, siginfo->si_status);
}

// Makes sure that even if ChildExitDispatcher is destroyed in the
// HandleExit, it should not cause a crash.
TEST_F(ChildExitDispatcherTest, DestroyInHandleExit) {
  // If multiple children are terminated, SIGCHLD will be squashed.
  // Practically this happens if children are terminated in a short period.
  // However, it is not easy to reproduce the situation reliably,
  // instead, this test sets up in the following approach to simulate it;
  // - Block SIGCHLD.
  // - Create a subprocess, and terminate it.
  // - Consume SIGCHLD via signalfd without waitpid.
  // - Create another subprocess, and terminate it.
  ScopedSIGCHLDMask scoped_mask;
  signal_handler_.Init();

  // Create the first subprocess.
  pid_t child_pid1 = system_utils_.fork();
  if (child_pid1 == 0) {
    _Exit(EXIT_SUCCESS);
  }

  // Consume SIGCHLD.
  signal_handler_.RegisterHandler(
      SIGCHLD, base::BindLambdaForTesting([](const struct signalfd_siginfo&) {
        brillo::MessageLoop::current()->BreakLoop();
        return true;
      }));
  brillo_loop_.Run();
  signal_handler_.UnregisterHandler(SIGCHLD);

  // Create the second subprocess.
  pid_t child_pid2 = system_utils_.fork();
  if (child_pid2 == 0) {
    _Exit(EXIT_SUCCESS);
  }

  // Set up ChildExitDispatcher.
  base::Optional<siginfo_t> siginfo;
  std::unique_ptr<ChildExitDispatcher> dispatcher;
  FakeChildExitHandler fake_handler(
      base::BindLambdaForTesting([&siginfo, &dispatcher](const siginfo_t& s) {
        siginfo = s;
        dispatcher = nullptr;  // Delete the dispatcher.
        brillo::MessageLoop::current()->BreakLoop();
        return true;
      }));
  dispatcher = std::make_unique<ChildExitDispatcher>(
      &signal_handler_, std::vector<ChildExitHandler*>{&fake_handler});

  // Spin the message loop.
  brillo_loop_.Run();

  // Verify child termination has been reported to |fake_handler|.
  ASSERT_TRUE(siginfo.has_value());
  EXPECT_EQ(child_pid1, siginfo->si_pid);
  EXPECT_EQ(SIGCHLD, siginfo->si_signo);
  EXPECT_EQ(static_cast<int>(CLD_EXITED), siginfo->si_code);
  EXPECT_EQ(EXIT_SUCCESS, siginfo->si_status);

  // No pending child is expected.
  siginfo_t info;
  ASSERT_EQ(-1, waitid(P_ALL, 0, &info, WEXITED | WNOHANG));
  EXPECT_EQ(errno, ECHILD);
}

}  // namespace login_manager
