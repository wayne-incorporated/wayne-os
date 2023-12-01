// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "syslog-cat/syslogcat.h"

#include <memory>
#include <optional>

#include <sys/socket.h>
#include <sys/un.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

namespace {

base::ScopedFD CreateDomainSocket(const base::FilePath& path) {
  base::ScopedFD peer(
      HANDLE_EINTR(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));

  struct sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  CHECK_GT(sizeof(addr.sun_path), path.value().length());
  strncpy(addr.sun_path, path.value().c_str(), sizeof(addr.sun_path));
  if (bind(peer.get(), (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    PLOG(ERROR) << "bind";
    return base::ScopedFD();
  }

  if (listen(peer.get(), 1) == -1) {
    PLOG(ERROR) << "listen";
    return base::ScopedFD();
  }

  return peer;
}

std::optional<std::string> AcceptAndReadFromSocket(int fd, int size) {
  struct sockaddr_un sun_client = {};
  socklen_t socklen = sizeof(sun_client);

  base::ScopedFD fd_client(
      HANDLE_EINTR(accept(fd, (struct sockaddr*)&sun_client, &socklen)));
  if (!fd_client.is_valid())
    return std::nullopt;

  const size_t kBufSize = 1000;
  char buf[kBufSize];
  CHECK_GT(kBufSize, size);
  EXPECT_TRUE(base::ReadFromFD(fd_client.get(), buf, size));
  return std::string(buf, size);
}

}  // anonymous namespace

class SyslogCatTest : public ::testing::Test {
 protected:
  int GetStdOutFd() const {
    CHECK(sock_stdout_.is_valid());
    return sock_stdout_.get();
  }
  int GetStdErrFd() const {
    CHECK(sock_stderr_.is_valid());
    return sock_stderr_.get();
  }

  pid_t ForkAndExecuteSyslogCat(
      const std::vector<const char*>& target_command) {
    const char kIdentifier[] = "IDENT";
    const int kSeverityStdout = 6;
    const int kSeverityStderr = 4;

    pid_t child_pid = fork();
    if (child_pid == 0) {
      // As a child process.
      ExecuteCommandWithRedirection(
          target_command[0], target_command, kIdentifier, kSeverityStdout,
          kSeverityStderr, sock_path_stdout_, sock_path_stderr_);

      return -1;
    } else {
      // As a parent process.
      // Wait for the child process to terminate.
      wait(0);

      return child_pid;
    }
  }

 private:
  void SetUp() override {
    base::FilePath directory;
    CHECK(base::GetTempDir(&directory));
    CHECK(base::CreateTemporaryDirInDir(directory, "syslogcat-test",
                                        &temp_directory_));

    sock_path_stdout_ = temp_directory_.Append("stdout.sock");
    sock_path_stderr_ = temp_directory_.Append("stderr.sock");

    sock_stdout_ = CreateDomainSocket(sock_path_stdout_);
    ASSERT_TRUE(sock_stdout_.is_valid());
    sock_stderr_ = CreateDomainSocket(sock_path_stderr_);
    ASSERT_TRUE(sock_stderr_.is_valid());
  }

  void TearDown() override { base::DeletePathRecursively(temp_directory_); }

  base::FilePath temp_directory_;
  base::FilePath sock_path_stdout_;
  base::FilePath sock_path_stderr_;
  base::ScopedFD sock_stdout_;
  base::ScopedFD sock_stderr_;
};

TEST_F(SyslogCatTest, Echo) {
  pid_t child_pid = ForkAndExecuteSyslogCat(
      std::vector<const char*>({"/bin/echo", "1234567890", NULL}));

  std::string expected_stdout =
      base::StringPrintf("TAG=IDENT[%d]\nPRIORITY=6\n\n1234567890", child_pid);
  std::optional<std::string> actual_stdout =
      AcceptAndReadFromSocket(GetStdOutFd(), expected_stdout.length());
  EXPECT_TRUE(actual_stdout.has_value());
  EXPECT_EQ(expected_stdout, *actual_stdout);

  std::string expected_stderr =
      base::StringPrintf("TAG=IDENT[%d]\nPRIORITY=4\n\n", child_pid);
  std::optional<std::string> actual_stderr =
      AcceptAndReadFromSocket(GetStdErrFd(), expected_stderr.length());
  EXPECT_TRUE(actual_stderr.has_value());
  EXPECT_EQ(expected_stderr, *actual_stderr);
}

TEST_F(SyslogCatTest, StdErr) {
  pid_t child_pid = ForkAndExecuteSyslogCat(std::vector<const char*>(
      {"/bin/bash", "-c", ">&2 echo 1234567890", NULL}));

  std::string expected_stdout =
      base::StringPrintf("TAG=IDENT[%d]\nPRIORITY=6\n\n", child_pid);
  std::optional<std::string> actual_stdout =
      AcceptAndReadFromSocket(GetStdOutFd(), expected_stdout.length());
  EXPECT_TRUE(actual_stdout.has_value());
  EXPECT_EQ(expected_stdout, *actual_stdout);

  std::string expected_stderr =
      base::StringPrintf("TAG=IDENT[%d]\nPRIORITY=4\n\n1234567890", child_pid);
  std::optional<std::string> actual_stderr =
      AcceptAndReadFromSocket(GetStdErrFd(), expected_stderr.length());
  EXPECT_TRUE(actual_stderr.has_value());
  EXPECT_EQ(expected_stderr, *actual_stderr);
}

TEST_F(SyslogCatTest, StdOutAndErr) {
  pid_t child_pid = ForkAndExecuteSyslogCat(std::vector<const char*>(
      {"/bin/bash", "-c", "echo STDOUT; echo STDERR >&2; echo HELLO.", NULL}));

  std::string expected_stdout = base::StringPrintf(
      "TAG=IDENT[%d]\nPRIORITY=6\n\nSTDOUT\nHELLO.", child_pid);
  std::optional<std::string> actual_stdout =
      AcceptAndReadFromSocket(GetStdOutFd(), expected_stdout.length());
  EXPECT_TRUE(actual_stdout.has_value());
  EXPECT_EQ(expected_stdout, *actual_stdout);

  std::string expected_stderr =
      base::StringPrintf("TAG=IDENT[%d]\nPRIORITY=4\n\nSTDERR", child_pid);
  std::optional<std::string> actual_stderr =
      AcceptAndReadFromSocket(GetStdErrFd(), expected_stderr.length());
  EXPECT_TRUE(actual_stderr.has_value());
  EXPECT_EQ(expected_stderr, *actual_stderr);
}
