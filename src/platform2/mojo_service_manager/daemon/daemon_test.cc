// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/socket.h>
#include <sysexits.h>

#include <cstring>
#include <optional>
#include <string>
#include <utility>

#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/bind.h>
#include <base/test/test_timeouts.h>
#include <base/threading/thread.h>
#include <brillo/process/process.h>
#include <brillo/process/process_reaper.h>
#include <gtest/gtest.h>

#include "mojo_service_manager/daemon/daemon.h"
#include "mojo_service_manager/daemon/daemon_test_helper.h"

namespace chromeos {
namespace mojo_service_manager {
namespace {

constexpr char kFakeSecurityContext[] = "u:r:cros_fake:s0";
constexpr char kDaemonTestHelperExecName[] = "daemon_test_helper";
constexpr char kTestSocketName[] = "test_socket";

class DaemonTest : public ::testing::Test {
 public:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  base::FilePath GetSocketPath() {
    return temp_dir_.GetPath().Append(kTestSocketName);
  }

  void RunDaemonAndExpectTestSubprocessResult(Daemon::Delegate* delegate,
                                              DaemonTestHelperResult result) {
    Daemon daemon{delegate, GetSocketPath(), {}, Configuration{}};
    brillo::ProcessImpl process;
    process.AddArg(base::CommandLine::ForCurrentProcess()
                       ->GetProgram()
                       .DirName()
                       .Append(kDaemonTestHelperExecName)
                       .value());
    process.AddArg(base::StringPrintf("--%s=%s", kSocketPathSwitch,
                                      GetSocketPath().value().c_str()));
    process.Start();
    brillo::ProcessReaper reaper;
    reaper.Register(&daemon);
    reaper.WatchForChild(FROM_HERE, process.pid(),
                         base::BindLambdaForTesting([&](const siginfo_t& info) {
                           EXPECT_EQ(info.si_pid, process.pid());
                           // Now child process has stopped so we should release
                           // it to prevent it being killed again.
                           process.Release();
                           EXPECT_EQ(info.si_code, CLD_EXITED);
                           EXPECT_EQ(info.si_status, static_cast<int>(result));
                           daemon.Quit();
                         }));
    EXPECT_EQ(daemon.Run(), EX_OK);
  }

 private:
  base::ScopedTempDir temp_dir_;
};

// Fake Daemon::Delegate to return fake |getsockopt|. If the expected field is
// set to nullopt, the |getsockopt| returns error when trying to report that
// field.
class FakeDelegate : public Daemon::Delegate {
 public:
  FakeDelegate(std::optional<struct ucred> ucred = std::nullopt,
               std::optional<std::string> security_context = std::nullopt);
  FakeDelegate(const FakeDelegate&) = delete;
  FakeDelegate& operator=(const FakeDelegate&) = delete;
  ~FakeDelegate() override;

  // Overrides Daemon::Delegate.
  int GetSockOpt(const base::ScopedFD& socket,
                 int level,
                 int optname,
                 void* optval,
                 socklen_t* optlen) const override;
  ServicePolicyMap LoadPolicyFiles(
      const std::vector<base::FilePath>& policy_dir_paths) const override;

 private:
  std::optional<struct ucred> ucred_;

  std::optional<std::string> security_context_;
};

FakeDelegate::FakeDelegate(std::optional<struct ucred> ucred,
                           std::optional<std::string> security_context)
    : ucred_(std::move(ucred)),
      security_context_(std::move(security_context)) {}

FakeDelegate::~FakeDelegate() = default;

int FakeDelegate::GetSockOpt(const base::ScopedFD& socket,
                             int level,
                             int optname,
                             void* optval,
                             socklen_t* optlen) const {
  switch (optname) {
    case SO_PEERCRED:
      if (!ucred_)
        return -1;
      CHECK_EQ(*optlen, sizeof(struct ucred));
      *reinterpret_cast<struct ucred*>(optval) = ucred_.value();
      return 0;
    case SO_PEERSEC:
      if (!security_context_)
        return -1;
      CHECK_GE(*optlen, security_context_->size());
      *optlen = security_context_->size();
      strncpy(reinterpret_cast<char*>(optval), security_context_->c_str(),
              security_context_->size());
      return 0;
    default:
      CHECK(false);
      return 0;
  }
}

ServicePolicyMap FakeDelegate::LoadPolicyFiles(
    const std::vector<base::FilePath>& policy_dir_paths) const {
  return ServicePolicyMap{};
}

TEST_F(DaemonTest, FailToListenSocket) {
  // Create the socket file so the daemon will fail to create it.
  ASSERT_TRUE(base::WriteFile(GetSocketPath(), "test"));
  FakeDelegate delegate{};
  Daemon daemon{&delegate, GetSocketPath(), {}, Configuration{}};
  EXPECT_NE(daemon.Run(), EX_OK);
}

TEST_F(DaemonTest, FailToGetSocketCred) {
  // Set ucred to nullopt to fail the test.
  FakeDelegate delegate{std::nullopt, kFakeSecurityContext};
  RunDaemonAndExpectTestSubprocessResult(
      &delegate, DaemonTestHelperResult::kResetWithOsError);
}

TEST_F(DaemonTest, FailToGetSocketSecurityContext) {
  // Set security context to nullopt to fail the test.
  struct ucred ucred = {};
  FakeDelegate delegate{ucred, std::nullopt};
  RunDaemonAndExpectTestSubprocessResult(
      &delegate, DaemonTestHelperResult::kResetWithOsError);
}

TEST_F(DaemonTest, FailToGetSocketSecurityContextEmptyString) {
  // Set security context to empty string to fail the test.
  struct ucred ucred = {};
  FakeDelegate delegate{ucred, std::string()};
  RunDaemonAndExpectTestSubprocessResult(
      &delegate, DaemonTestHelperResult::kResetWithOsError);
}

TEST_F(DaemonTest, Connect) {
  struct ucred ucred = {};
  FakeDelegate delegate{ucred, kFakeSecurityContext};
  RunDaemonAndExpectTestSubprocessResult(
      &delegate, DaemonTestHelperResult::kConnectSuccessfully);
}

TEST(DaemonUtilTest, GetSEContextStringFromChar) {
  // The length doesn't contain the null-terminator.
  EXPECT_EQ(GetSEContextStringFromChar("", 0), "");
  EXPECT_EQ(GetSEContextStringFromChar("a", 1), "a");
  EXPECT_EQ(GetSEContextStringFromChar("aa", 2), "aa");

  // The length contains the null-terminator.
  EXPECT_EQ(GetSEContextStringFromChar("\0", 1), "");
  EXPECT_EQ(GetSEContextStringFromChar("a\0", 2), "a");
  EXPECT_EQ(GetSEContextStringFromChar("aa\0", 3), "aa");

  // The length doesn't contain the null-terminator and the last char is not
  // null-terminator.
  EXPECT_EQ(GetSEContextStringFromChar("a", 0), "");
  EXPECT_EQ(GetSEContextStringFromChar("aa", 1), "a");
  EXPECT_EQ(GetSEContextStringFromChar("aaa", 2), "aa");
}

}  // namespace
}  // namespace mojo_service_manager
}  // namespace chromeos
