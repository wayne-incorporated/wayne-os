// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/process.h"

#include <csignal>
#include <memory>
#include <ostream>
#include <utility>

#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <chromeos/libminijail.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/sandboxed_init.h"
#include "cros-disks/sandboxed_process.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::Contains;
using testing::ElementsAre;
using testing::IsEmpty;
using testing::IsSupersetOf;
using testing::Not;
using testing::PrintToStringParamName;
using testing::Return;
using testing::SizeIs;
using testing::StartsWith;
using testing::UnorderedElementsAre;
using testing::Values;

// Sets a signal handler for SIGALRM and an interval timer signaling SIGALRM at
// regular intervals.
class AlarmGuard {
 public:
  explicit AlarmGuard(const int timer_interval_ms) {
    CHECK(!old_handler_);
    count_ = 0;
    old_handler_ = signal(SIGALRM, &Handler);
    CHECK_NE(old_handler_, SIG_ERR);
    SetIntervalTimer(timer_interval_ms * 1000 /* microseconds */);
  }
  AlarmGuard(const AlarmGuard&) = delete;
  AlarmGuard& operator=(const AlarmGuard&) = delete;

  ~AlarmGuard() {
    SetIntervalTimer(0);
    CHECK_EQ(signal(SIGALRM, old_handler_), &Handler);
    old_handler_ = nullptr;
  }

  // Number of times SIGALRM has been received.
  static int count() { return count_; }

 private:
  static void Handler(int sig) {
    CHECK_EQ(sig, SIGALRM);
    ++count_;
  }

  static void SetIntervalTimer(const int usec) {
    const itimerval tv = {{0, usec}, {0, usec}};
    if (setitimer(ITIMER_REAL, &tv, nullptr) < 0) {
      PLOG(FATAL) << "Cannot set timer";
    }
  }

  // Number of times SIGALRM has been received.
  static int count_;

  using SigHandler = void (*)(int);
  static SigHandler old_handler_;
};

int AlarmGuard::count_ = 0;
AlarmGuard::SigHandler AlarmGuard::old_handler_ = nullptr;

std::string Read(const int fd) {
  char buffer[PIPE_BUF];

  LOG(INFO) << "Reading up to " << PIPE_BUF << " bytes from fd " << fd << "...";
  const ssize_t bytes_read = HANDLE_EINTR(read(fd, buffer, PIPE_BUF));
  PLOG_IF(FATAL, bytes_read < 0) << "Cannot read from fd " << fd;

  LOG(INFO) << "Read " << bytes_read << " bytes from fd " << fd;
  return std::string(buffer, bytes_read);
}

void Write(const int fd, base::StringPiece s) {
  while (!s.empty()) {
    const ssize_t bytes_written = HANDLE_EINTR(write(fd, s.data(), s.size()));
    PLOG_IF(FATAL, bytes_written < 0) << "Cannot write to fd " << fd;

    s.remove_prefix(bytes_written);
  }
}

// A mock Process class for testing the Process base class.
class ProcessUnderTest : public Process {
 public:
  MOCK_METHOD(pid_t, StartImpl, (base::ScopedFD, base::ScopedFD), (override));
  MOCK_METHOD(int, WaitImpl, (), (override));
  MOCK_METHOD(int, WaitNonBlockingImpl, (), (override));
};

struct ProcessFactory {
  base::StringPiece name;
  std::unique_ptr<SandboxedProcess> (*make_process)();
};

std::ostream& operator<<(std::ostream& out, const ProcessFactory& x) {
  return out << x.name;
}

}  // namespace

class ProcessTest : public ::testing::Test {
 protected:
  ProcessUnderTest process_;
};

TEST_F(ProcessTest, GetArguments) {
  const char* const kTestArguments[] = {"/bin/ls", "-l", "", "."};
  for (const char* test_argument : kTestArguments) {
    process_.AddArgument(test_argument);
  }

  EXPECT_THAT(process_.arguments(), ElementsAre("/bin/ls", "-l", "", "."));

  char* const* arguments = process_.GetArguments();
  EXPECT_NE(nullptr, arguments);
  for (const char* test_argument : kTestArguments) {
    EXPECT_STREQ(test_argument, *arguments);
    ++arguments;
  }
  EXPECT_EQ(nullptr, *arguments);
}

TEST_F(ProcessTest, GetArgumentsWithNoArgumentsAdded) {
  char* const* arguments = process_.GetArguments();
  EXPECT_NE(nullptr, arguments);
  EXPECT_EQ(nullptr, *arguments);
}

TEST_F(ProcessTest, Run_Success) {
  process_.AddArgument("foo");
  EXPECT_CALL(process_, StartImpl(_, _)).WillOnce(Return(123));
  EXPECT_CALL(process_, WaitImpl()).Times(0);
  EXPECT_CALL(process_, WaitNonBlockingImpl()).WillOnce(Return(42));
  EXPECT_EQ(process_.pid(), Process::kInvalidProcessId);
  EXPECT_EQ(process_.Run(), 42);
  EXPECT_NE(process_.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process_.GetCapturedOutput(), IsEmpty());
}

TEST_F(ProcessTest, Run_Fail) {
  process_.AddArgument("foo");
  EXPECT_CALL(process_, StartImpl(_, _)).WillOnce(Return(-1));
  EXPECT_CALL(process_, WaitImpl()).Times(0);
  EXPECT_CALL(process_, WaitNonBlockingImpl()).Times(0);
  EXPECT_EQ(process_.Run(), -1);
  EXPECT_EQ(process_.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process_.GetCapturedOutput(), IsEmpty());
}

class ProcessRunTest : public ::testing::TestWithParam<ProcessFactory> {
 public:
  ProcessRunTest() {
    // Ensure that we get an error message if Minijail crashes.
    // TODO(crbug.com/1007098) Remove the following line or this comment
    // depending on how this bug is resolved.
    minijail_log_to_fd(STDERR_FILENO, 0);
  }

  const std::unique_ptr<SandboxedProcess> process_ = GetParam().make_process();
};

TEST_P(ProcessRunTest, RunReturnsZero) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("exit 0");
  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), IsEmpty());
}

TEST_P(ProcessRunTest, WaitReturnsZero) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("exit 0");
  EXPECT_TRUE(process.Start());
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_EQ(process.Wait(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunReturnsNonZero) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("exit 42");
  EXPECT_EQ(process.Run(), 42);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), IsEmpty());
}

TEST_P(ProcessRunTest, WaitReturnsNonZero) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("exit 42");
  EXPECT_TRUE(process.Start());
  EXPECT_EQ(process.Wait(), 42);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunKilledBySigKill) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("kill -KILL $$; sleep 1000");
  EXPECT_EQ(process.Run(), MINIJAIL_ERR_SIG_BASE + SIGKILL);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), IsEmpty());
}

TEST_P(ProcessRunTest, WaitKilledBySigKill) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("kill -KILL $$; sleep 1000");
  EXPECT_TRUE(process.Start());
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_SIG_BASE + SIGKILL);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunKilledBySigSys) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("kill -SYS $$; sleep 1000");
  EXPECT_EQ(process.Run(), MINIJAIL_ERR_JAIL);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), IsEmpty());
}

TEST_P(ProcessRunTest, WaitKilledBySigSys) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("kill -SYS $$; sleep 1000");
  EXPECT_TRUE(process.Start());
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_JAIL);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, ExternallyKilledBySigKill) {
  SandboxedProcess& process = *process_;
  process.AddArgument("/bin/bash");
  process.AddArgument("-c");

  // Pipe to block the child process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the child process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(
      R"(
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process.Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for child process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Send SIGKILL to child process.
  const pid_t pid = process.pid();
  EXPECT_NE(pid, Process::kInvalidProcessId);
  LOG(INFO) << "Sending SIGKILL to PID " << pid;
  EXPECT_EQ(kill(pid, SIGKILL), 0);

  // Wait for child process to finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_SIG_BASE + SIGKILL);
  EXPECT_EQ(process.pid(), pid);
}

TEST_P(ProcessRunTest, ExternallyKilledBySigTerm) {
  SandboxedProcess& process = *process_;
  process.SetKillPidNamespace(true);

  process.AddArgument("/bin/bash");
  process.AddArgument("-c");

  // Pipe to block the child process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the child process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(
      R"(
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process.Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for child process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Send SIGTERM to child process.
  const pid_t pid = process.pid();
  EXPECT_NE(pid, Process::kInvalidProcessId);
  LOG(INFO) << "Sending SIGTERM to PID " << pid;
  EXPECT_EQ(kill(pid, SIGTERM), 0);

  // Wait for child process to finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_SIG_BASE + SIGTERM);
  EXPECT_EQ(process.pid(), pid);
}

TEST_P(ProcessRunTest, RunCannotFindCommand) {
  Process& process = *process_;
  process.AddArgument("non existing command");
  EXPECT_EQ(process.Run(), MINIJAIL_ERR_NO_COMMAND);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, WaitCannotFindCommand) {
  Process& process = *process_;
  process.AddArgument("non existing command");
  EXPECT_TRUE(process.Start());
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_NO_COMMAND);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunCannotRunCommand) {
  Process& process = *process_;
  process.AddArgument("/dev/null");
  EXPECT_EQ(process.Run(), MINIJAIL_ERR_NO_ACCESS);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, WaitCannotRunCommand) {
  Process& process = *process_;
  process.AddArgument("/dev/null");
  EXPECT_TRUE(process.Start());
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_NO_ACCESS);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, CapturesInterleavedOutputs) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument(R"(
      printf 'Line 1\nLine 2\n' >&1;
      printf 'Line 3\nLine 4\n' >&2;
      printf 'Line 5\n' >&1;
      printf 'Line 6' >&2;
    )");

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(),
              UnorderedElementsAre("Line 1", "Line 2", "Line 3", "Line 4",
                                   "Line 5", "Line 6"));
}

// Tests Process when the child process closes its stdout and stderr shortly
// before exiting.
TEST_P(ProcessRunTest, ClosesStdOutBeforeExiting) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument(R"(
      echo Hi
      exec 1>&-;
      exec 2>&-;
      sleep 1;
      exit 42;
    )");

  EXPECT_EQ(process.Run(), 42);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), ElementsAre("Hi"));
}

TEST_P(ProcessRunTest, CapturesLotsOfOutputData) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument(R"(
      for i in $(seq 1 1000); do
        printf 'Message %i\n' $i >&1;
        printf 'Error %i\n' $i >&2;
      done;
    )");

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), SizeIs(2000));
}

TEST_P(ProcessRunTest, DoesNotBlockWhenNotCapturingOutput) {
  SandboxedProcess& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");

  // Pipe to monitor the process and wait for it to finish without calling
  // Process::Wait.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(R"(
      printf '%%01000i\n' $(seq 1 100) >&1;
      printf '%%01000i\n' $(seq 1 100) >&2;
      printf 'End' >&%d;
      exit 42;
    )",
                                         to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());

  // This process generates lots of output on stdout and stderr, ie more than
  // what a pipe can hold without blocking. If the pipes connected to stdout and
  // stderr were not drained, they would fill, the process would stall and
  // process.Wait() would block forever. If the pipes were closed, the process
  // would be killed by a SIGPIPE. With drained pipes, the process finishes
  // normally and its return code should be visible.
  EXPECT_TRUE(process.Start());

  // The process should finish normally without the parent having to call
  // Process::Wait() first.
  to_wait.child_fd.reset();
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "End");
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");

  EXPECT_EQ(process.Wait(), 42);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunDoesNotBlockWhenReadingFromStdIn) {
  Process& process = *process_;
  process.AddArgument("/bin/cat");

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), IsEmpty());
}

TEST_P(ProcessRunTest, ReadsFromStdIn) {
  Process& process = *process_;
  process.AddArgument("/bin/cat");

  EXPECT_EQ(process.input(), "");
  const std::string input = "Line 1\nLine 2\nLine 3";
  process.SetStdIn(input);
  EXPECT_EQ(process.input(), input);

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(),
              ElementsAre("Line 1", "Line 2", "Line 3"));
}

TEST_P(ProcessRunTest, ReadsLotsFromStdIn) {
  Process& process = *process_;
  process.AddArgument("/bin/wc");
  process.AddArgument("-c");

  // 4KB of data should be passed without error nor truncation.
  process.SetStdIn(std::string(4096, 'x'));
  EXPECT_THAT(process.input(), SizeIs(4096));

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), ElementsAre("4096"));
}

TEST_P(ProcessRunTest, TruncatesDataFromStdIn) {
  Process& process = *process_;
  process.AddArgument("/bin/wc");
  process.AddArgument("-c");

  // 100KB of data should be truncated.
  process.SetStdIn(std::string(100'000, 'x'));

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), ElementsAre(Not("100000")));
}

TEST_P(ProcessRunTest, WaitDoesNotBlockWhenReadingFromStdIn) {
  Process& process = *process_;
  process.AddArgument("/bin/cat");
  process.SetStdIn(std::string(100'000, 'x'));

  // By default, /bin/cat reads from stdin. If the pipe connected to stdin was
  // left open, the process would block indefinitely while reading from it.
  EXPECT_TRUE(process.Start());
  EXPECT_EQ(process.Wait(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunDoesNotWaitForBackgroundProcessToFinish) {
  SandboxedProcess& process = *process_;
  process.AddArgument("/bin/bash");
  process.AddArgument("-c");

  // Pipe to unblock the background process and allow it to finish.
  SubprocessPipe to_continue(SubprocessPipe::kParentToChild);

  // Pipe to monitor the background process and wait for it to finish.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(R"(
      (
        exec 0<&-;
        exec 1>&-;
        exec 2>&-;
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
      )&
      printf 'Started background process %%i\n' $!
      exit 5;
    )",
                                         to_wait.child_fd.get(),
                                         to_continue.child_fd.get(),
                                         to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_continue.child_fd.get());

  LOG(INFO) << "Running launcher process";
  EXPECT_EQ(process.Run(), 5);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(),
              ElementsAre(StartsWith("Started background process")));

  LOG(INFO) << "Closing unused fds";
  to_continue.child_fd.reset();
  to_wait.child_fd.reset();

  LOG(INFO) << "Waiting for background process to confirm starting";
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  LOG(INFO) << "Unblocking background process";
  Write(to_continue.parent_fd.get(), "Continue\n");

  LOG(INFO) << "Waiting for background process to finish";
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Continue and End\n");
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");

  LOG(INFO) << "Background process finished";
}

TEST_P(ProcessRunTest, WaitDoesNotWaitForBackgroundProcessToFinish) {
  SandboxedProcess& process = *process_;
  process.AddArgument("/bin/bash");
  process.AddArgument("-c");

  // Pipe to unblock the background process and allow it to finish.
  SubprocessPipe to_continue(SubprocessPipe::kParentToChild);

  // Pipe to monitor the background process and wait for it to finish.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(R"(
      (
        exec 0<&-;
        exec 1>&-;
        exec 2>&-;
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
      )&
      exit 5;
    )",
                                         to_wait.child_fd.get(),
                                         to_continue.child_fd.get(),
                                         to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_continue.child_fd.get());

  LOG(INFO) << "Starting launcher process";
  EXPECT_TRUE(process.Start());

  LOG(INFO) << "Waiting for launcher process to finish";
  EXPECT_EQ(process.Wait(), 5);

  LOG(INFO) << "Closing unused fds";
  to_continue.child_fd.reset();
  to_wait.child_fd.reset();

  LOG(INFO) << "Waiting for background process to confirm starting";
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  LOG(INFO) << "Unblocking background process";
  Write(to_continue.parent_fd.get(), "Continue\n");

  LOG(INFO) << "Waiting for background process to finish";
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Continue and End\n");
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");

  LOG(INFO) << "Background process finished";
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
}

TEST_P(ProcessRunTest, RunUndisturbedBySignals) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument(R"(
      for i in $(seq 1 100); do
        printf 'Line %0100i\n' $i;
        sleep 0.01;
      done;
      exit 42;
    )");

  // Activate an interval timer.
  const AlarmGuard guard(13 /* milliseconds */);
  EXPECT_EQ(process.Run(), 42);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_GT(AlarmGuard::count(), 0);
  // This checks that crbug.com/1005590 is fixed.
  EXPECT_THAT(process.GetCapturedOutput(), SizeIs(100));
}

TEST_P(ProcessRunTest, WaitUndisturbedBySignals) {
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument(R"(
      sleep 1;
      exit 42;
    )");

  // Activate an interval timer.
  const AlarmGuard guard(13 /* milliseconds */);
  EXPECT_TRUE(process.Start());
  EXPECT_EQ(process.Wait(), 42);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_GT(AlarmGuard::count(), 0);
}

TEST_P(ProcessRunTest, PassCurrentEnvironment) {
  EXPECT_EQ(setenv("OLD_VAR_1", "Old 1", 0), 0);
  EXPECT_EQ(setenv("OLD_VAR_2", "Old 2", 0), 0);
  Process& process = *process_;
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("set");

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), Contains("OLD_VAR_1='Old 1'"));
  EXPECT_THAT(process.GetCapturedOutput(), Contains("OLD_VAR_2='Old 2'"));
  EXPECT_EQ(unsetenv("OLD_VAR_1"), 0);
  EXPECT_EQ(unsetenv("OLD_VAR_2"), 0);
}

TEST_P(ProcessRunTest, AppendExtraEnvironment) {
  EXPECT_EQ(setenv("OLD_VAR_1", "Old 1", 0), 0);
  EXPECT_EQ(setenv("OLD_VAR_2", "Old 2", 0), 0);
  Process& process = *process_;
  EXPECT_THAT(process.environment(), IsEmpty());
  process.AddEnvironmentVariable("MY_VAR_1", "");
  process.AddEnvironmentVariable("MY_VAR_2", " ");
  process.AddEnvironmentVariable("MY_VAR_3", "=");
  process.AddEnvironmentVariable("MY_VAR_4",
                                 R"(abc 123 ~`!@#$%^&*()_-+={[}]|\:;"'<,>.?/)");
  EXPECT_THAT(
      process.environment(),
      ElementsAre("MY_VAR_1=", "MY_VAR_2= ", "MY_VAR_3==",
                  R"(MY_VAR_4=abc 123 ~`!@#$%^&*()_-+={[}]|\:;"'<,>.?/)"));
  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument("set");

  EXPECT_EQ(process.Run(), 0);
  EXPECT_NE(process.pid(), Process::kInvalidProcessId);
  EXPECT_THAT(process.GetCapturedOutput(), Contains("OLD_VAR_1='Old 1'"));
  EXPECT_THAT(process.GetCapturedOutput(), Contains("OLD_VAR_2='Old 2'"));
  EXPECT_THAT(process.GetCapturedOutput(), Contains("MY_VAR_1=''"));
  EXPECT_THAT(process.GetCapturedOutput(), Contains("MY_VAR_2=' '"));
  EXPECT_THAT(process.GetCapturedOutput(), Contains("MY_VAR_3='='"));
  EXPECT_THAT(
      process.GetCapturedOutput(),
      Contains(R"(MY_VAR_4='abc 123 ~`!@#$%^&*()_-+={[}]|\:;"'"'"'<,>.?/')"));
  EXPECT_EQ(unsetenv("OLD_VAR_1"), 0);
  EXPECT_EQ(unsetenv("OLD_VAR_2"), 0);
}

INSTANTIATE_TEST_SUITE_P(ProcessRun,
                         ProcessRunTest,
                         Values(ProcessFactory{
                             "SandboxedProcess",
                             []() {
                               return std::make_unique<SandboxedProcess>();
                             }}),
                         PrintToStringParamName());

// TODO(crbug.com/1023727) Make PID namespace work on ARM and ARM64.
#if defined(__x86_64__)
INSTANTIATE_TEST_SUITE_P(ProcessRunAsRoot,
                         ProcessRunTest,
                         Values(ProcessFactory{
                             "WithPidNamespace",
                             []() {
                               auto process =
                                   std::make_unique<SandboxedProcess>();
                               process->NewPidNamespace();
                               return process;
                             }}),
                         PrintToStringParamName());

// Tests that, when the 'launcher' process running in a PID namespace does not
// terminate within the grace period when receiving a SIGTERM, then it is killed
// by SIGKILL at the expiration of this grace period.
TEST(PidNamespaceRunAsRootTest, LauncherDoesNotTerminateOnSigTerm) {
  SandboxedProcess process;
  process.NewPidNamespace();
  process.SetKillPidNamespace(true);

  process.AddArgument("/bin/bash");
  process.AddArgument("-c");

  // Pipe to block the 'launcher' process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the 'launcher' process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(
      R"(
        trap 'echo Launcher process ignored a SIGTERM' SIGTERM
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process.Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for 'launcher' process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Send SIGTERM to 'init' process.
  const pid_t pid = process.pid();
  EXPECT_NE(pid, Process::kInvalidProcessId);
  LOG(INFO) << "Sending SIGTERM to PID " << pid;
  base::ElapsedTimer timer;
  EXPECT_EQ(kill(pid, SIGTERM), 0);

  // Wait for 'launcher' process to finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_SIG_BASE + SIGKILL);
  // It should have taken a bit more than 2 seconds (grace period) for the
  // 'init' process to terminate, which would have killed the 'launcher' process
  // too.
  EXPECT_GT(timer.Elapsed(), base::Seconds(2));
  EXPECT_EQ(process.pid(), pid);
}

// Tests that, when the 'launcher' process running in a PID namespace does not
// terminate within the grace period when receiving a SIGTERM, then it is killed
// by SIGKILL at the expiration of this grace period. Repeatedly sending SIGTERM
// to the 'init' process does not speed up nor slow down the termination.
TEST(PidNamespaceRunAsRootTest, RepeatedSigTerm) {
  SandboxedProcess process;
  process.NewPidNamespace();
  process.SetKillPidNamespace(true);

  process.AddArgument("/bin/bash");
  process.AddArgument("-c");

  // Pipe to block the 'launcher' process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the 'launcher' process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(
      R"(
        trap 'echo Launcher process ignored a SIGTERM' SIGTERM
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process.Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for 'launcher' process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Repeatedly send SIGTERM to 'init' process.
  const pid_t pid = process.pid();
  EXPECT_NE(pid, Process::kInvalidProcessId);
  base::ElapsedTimer timer;

  while (!process.IsFinished()) {
    LOG(INFO) << "Sending SIGTERM to PID " << pid;
    EXPECT_EQ(kill(pid, SIGTERM), 0);
    usleep(100'000);
  }

  // Wait for 'launcher' process to finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
  EXPECT_EQ(process.Wait(), MINIJAIL_ERR_SIG_BASE + SIGKILL);
  // It should have taken a bit more than 2 seconds (grace period) for the
  // 'init' process to terminate, which would have killed the 'launcher' process
  // too.
  EXPECT_GT(timer.Elapsed(), base::Seconds(2));
  EXPECT_EQ(process.pid(), pid);
}

TEST(PidNamespaceRunAsRootTest, SimulatesProgress) {
  SandboxedProcess process;
  process.NewPidNamespace();
  process.SimulateProgressForTesting();

  process.AddArgument("/bin/sh");
  process.AddArgument("-c");
  process.AddArgument(R"(
      echo Finished;
      exit 42;
    )");

  base::ElapsedTimer timer;
  EXPECT_EQ(process.Run(), 42);
  EXPECT_GT(timer.Elapsed(), base::Seconds(10));
  EXPECT_THAT(process.GetCapturedOutput(), SizeIs(101));
  EXPECT_THAT(process.GetCapturedOutput(),
              IsSupersetOf({"Simulating progress 0%", "Simulating progress 73%",
                            "Simulating progress 99%", "Finished"}));
}

// Tests that the PID namespace is killed when the SandboxedProcess object is
// deleted and the SetKillPidNamespace(true) method has been called.
TEST(PidNamespaceRunAsRootTest, DeletingProcessObjectKillsPidNamespace) {
  std::unique_ptr<SandboxedProcess> process =
      std::make_unique<SandboxedProcess>();
  process->NewPidNamespace();
  process->SetKillPidNamespace(true);

  process->AddArgument("/bin/sh");
  process->AddArgument("-c");

  // Pipe to block the child process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the child process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process->AddArgument(base::StringPrintf(
      R"(
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process->PreserveFile(to_wait.child_fd.get());
  process->PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process->Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for child process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Destroy the process object.
  process.reset();

  // Wait for child process to finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
}

// Tests that the PID namespace is not killed when the SandboxedProcess object
// is deleted and the SetKillPidNamespace() method has not been called.
TEST(PidNamespaceRunAsRootTest, DeletingProcessObjectDoesNotKillPidNamespace) {
  std::unique_ptr<SandboxedProcess> process =
      std::make_unique<SandboxedProcess>();
  process->NewPidNamespace();

  process->AddArgument("/bin/sh");
  process->AddArgument("-c");

  // Pipe to block the child process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the child process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process->AddArgument(base::StringPrintf(
      R"(
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process->PreserveFile(to_wait.child_fd.get());
  process->PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process->Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for child process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Destroy the process object.
  process.reset();

  // Wait for longer than the 2-second grace period.
  sleep(3);

  // Unblock child process.
  Write(to_block.parent_fd.get(), "Continue");
  to_block.parent_fd.reset();

  // Wait for child process to continue and finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Continue and End\n");
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
}

// Tests that the PID namespace is not killed when its 'init' process receives a
// SIGTERM and the SetKillPidNamespace() method has not been called.
TEST(PidNamespaceRunAsRootTest, SigTermDoesNotKillPidNamespace) {
  SandboxedProcess process;
  process.NewPidNamespace();

  process.AddArgument("/bin/sh");
  process.AddArgument("-c");

  // Pipe to block the child process.
  SubprocessPipe to_block(SubprocessPipe::kParentToChild);

  // Pipe to monitor the child process.
  SubprocessPipe to_wait(SubprocessPipe::kChildToParent);

  process.AddArgument(base::StringPrintf(
      R"(
        printf 'Begin\n' >&%d;
        read line <&%d;
        printf '%%s and End\n' "$line" >&%d;
        exit 42;
    )",
      to_wait.child_fd.get(), to_block.child_fd.get(), to_wait.child_fd.get()));

  process.PreserveFile(to_wait.child_fd.get());
  process.PreserveFile(to_block.child_fd.get());

  EXPECT_TRUE(process.Start());

  // Close unused pipe ends.
  to_block.child_fd.reset();
  to_wait.child_fd.reset();

  // Wait for child process to start.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Begin\n");

  // Send SIGTERM to PID 'init' process.
  const pid_t pid = process.pid();
  EXPECT_NE(pid, Process::kInvalidProcessId);
  LOG(INFO) << "Sending SIGTERM to PID " << pid;
  EXPECT_EQ(kill(pid, SIGTERM), 0);

  // Wait for longer than the 2-second grace period.
  sleep(3);

  // Unblock child process.
  Write(to_block.parent_fd.get(), "Continue");
  to_block.parent_fd.reset();

  // Wait for child process to continue and finish.
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "Continue and End\n");
  EXPECT_EQ(Read(to_wait.parent_fd.get()), "");
  EXPECT_EQ(process.Wait(), 42);
}

#endif

}  // namespace cros_disks
