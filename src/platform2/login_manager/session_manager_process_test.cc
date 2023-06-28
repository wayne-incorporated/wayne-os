// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <base/bind.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/memory/ref_counted.h>
#include <base/optional.h>
#include <base/strings/string_util.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "login_manager/browser_job.h"
#include "login_manager/fake_browser_job.h"
#include "login_manager/fake_child_process.h"
#include "login_manager/fake_generator_job.h"
#include "login_manager/mock_device_policy_service.h"
#include "login_manager/mock_file_checker.h"
#include "login_manager/mock_liveness_checker.h"
#include "login_manager/mock_metrics.h"
#include "login_manager/mock_session_manager.h"
#include "login_manager/system_utils_impl.h"
#include "power_manager/proto_bindings/suspend.pb.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::Return;
using ::testing::Sequence;

namespace login_manager {

// Used as a fixture for the tests in this file.
// Gives useful shared functionality.
class SessionManagerProcessTest : public ::testing::Test {
 public:
  SessionManagerProcessTest()
      : manager_(nullptr),
        liveness_checker_(new MockLivenessChecker),
        session_manager_impl_(new MockSessionManager),
        must_destroy_mocks_(true) {}
  SessionManagerProcessTest(const SessionManagerProcessTest&) = delete;
  SessionManagerProcessTest& operator=(const SessionManagerProcessTest&) =
      delete;

  ~SessionManagerProcessTest() override {
    if (must_destroy_mocks_) {
      delete liveness_checker_;
      delete session_manager_impl_;
    }
  }

  void SetUp() override {
    brillo_loop_.SetAsCurrent();
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());

    aborted_browser_pid_path_ = tmpdir_.GetPath().Append("aborted_browser_pid");
  }

  void TearDown() override {
    must_destroy_mocks_ = !manager_.get();
    manager_ = nullptr;
  }

 protected:
  // kFakeEmail is NOT const so that it can be passed to methods that
  // implement dbus calls, which (of necessity) take bare gchar*.
  static char kFakeEmail[];
  static const pid_t kFakePid;
  static const int kExit;

  void MockUtils() { manager_->test_api().set_systemutils(&utils_); }

  void ExpectShutdown() {
    EXPECT_CALL(*session_manager_impl_, AnnounceSessionStoppingIfNeeded())
        .Times(1);
    EXPECT_CALL(*session_manager_impl_, AnnounceSessionStopped()).Times(1);
  }

  void ExpectLivenessChecking() {
    EXPECT_CALL(*liveness_checker_, Start()).Times(AtLeast(1));
    EXPECT_CALL(*liveness_checker_, Stop()).Times(AtLeast(1));
  }

  void ExpectOneJobReRun(FakeBrowserJob* job, int exit_status) {
    EXPECT_CALL(*job, KillEverything(SIGKILL, _)).Times(AnyNumber());
    EXPECT_CALL(*session_manager_impl_, ShouldEndSession(_))
        .WillRepeatedly(Return(false));
    // Return false once to allow the job to rerun. We then return true to stop
    // the loop; otherwise, the test will keep restarting the job forever.
    EXPECT_CALL(*job, ShouldStop())
        .WillOnce(Return(false))
        .WillOnce(Return(true));

    // Browser shutdown time is not tracked if browser does not request stop.
    EXPECT_CALL(metrics_, SendBrowserShutdownTime(_)).Times(0);

    job->set_fake_child_process(std::make_unique<FakeChildProcess>(
        kFakePid, exit_status, manager_->test_api()));
  }

  void InitManager(std::unique_ptr<BrowserJobInterface> job) {
    manager_ =
        new SessionManagerService(std::move(job), getuid(), base::nullopt,
                                  base::TimeDelta::FromSeconds(3), false,
                                  base::TimeDelta(), &metrics_, &utils_);
    manager_->test_api().set_liveness_checker(liveness_checker_);
    manager_->test_api().set_session_manager(session_manager_impl_);
    manager_->test_api().set_aborted_browser_pid_path(
        aborted_browser_pid_path_);
  }

  void SimpleRunManager() {
    ExpectShutdown();
    manager_->RunBrowser();
    brillo_loop_.Run();
  }

  void ForceRunLoop() { brillo_loop_.Run(); }

  FakeBrowserJob* CreateMockJobAndInitManager(bool schedule_exit) {
    FakeBrowserJob* job = new FakeBrowserJob("FakeBrowserJob", schedule_exit);
    InitManager(base::WrapUnique(job));

    job->set_fake_child_process(
        std::make_unique<FakeChildProcess>(kFakePid, 0, manager_->test_api()));

    return job;
  }

  int PackStatus(int status) { return __W_EXITCODE(status, 0); }
  int PackSignal(int signal) { return __W_EXITCODE(0, signal); }

  scoped_refptr<SessionManagerService> manager_;
  MockMetrics metrics_;
  SystemUtilsImpl utils_;
  base::FilePath aborted_browser_pid_path_;

  // These are bare pointers, not unique_ptrs, because we need to give them
  // to a SessionManagerService instance, but also be able to set expectations
  // on them after we hand them off.
  MockLivenessChecker* liveness_checker_;
  MockSessionManager* session_manager_impl_;

 private:
  bool must_destroy_mocks_;
  base::ScopedTempDir tmpdir_;
  brillo::BaseMessageLoop brillo_loop_;
};

// static
char SessionManagerProcessTest::kFakeEmail[] = "cmasone@whaaat.org";
const pid_t SessionManagerProcessTest::kFakePid = 4;
const int SessionManagerProcessTest::kExit = 1;

class HandleSuspendReadinessMethodMatcher
    : public ::testing::MatcherInterface<dbus::MethodCall*> {
 public:
  HandleSuspendReadinessMethodMatcher(int delay_id, int suspend_id)
      : delay_id_(delay_id), suspend_id_(suspend_id) {}

  bool MatchAndExplain(
      dbus::MethodCall* method_call,
      ::testing::MatchResultListener* listener) const override {
    // Make sure we've got the right kind of method call.
    if (method_call->GetInterface() != power_manager::kPowerManagerInterface) {
      *listener << "interface was " << method_call->GetInterface();
      return false;
    }

    if (method_call->GetMember() !=
        power_manager::kHandleSuspendReadinessMethod) {
      *listener << "method name was " << method_call->GetMember();
      return false;
    }

    // Check proto for correctness.
    power_manager::SuspendReadinessInfo info;
    dbus::MessageReader reader(method_call);
    reader.PopArrayOfBytesAsProto(&info);
    if (info.delay_id() != delay_id_) {
      *listener << "delay ID was " << info.delay_id();
      return false;
    }
    if (info.suspend_id() != suspend_id_) {
      *listener << "suspend ID was " << info.suspend_id();
      return false;
    }

    return true;
  }

  void DescribeTo(::std::ostream* os) const override {
    *os << "HandleSuspendReadiness method call with delay ID " << delay_id_
        << " and suspend ID " << suspend_id_;
  }

  void DescribeNegationTo(::std::ostream* os) const override {
    *os << "non-HandleSuspendReadiness method call, or method call "
        << "not with delay ID " << delay_id_ << " and suspend ID "
        << suspend_id_;
  }

 private:
  const int delay_id_;
  const int suspend_id_;
};

inline testing::Matcher<dbus::MethodCall*> HandleSuspendReadinessMethod(
    int delay_id, int suspend_id) {
  return MakeMatcher(
      new HandleSuspendReadinessMethodMatcher(delay_id, suspend_id));
}

class StopAllVmsMethodMatcher
    : public ::testing::MatcherInterface<dbus::MethodCall*> {
 public:
  StopAllVmsMethodMatcher() = default;

  bool MatchAndExplain(
      dbus::MethodCall* method_call,
      ::testing::MatchResultListener* listener) const override {
    // Make sure we've got the right kind of method call.
    if (method_call->GetInterface() !=
        vm_tools::concierge::kVmConciergeInterface) {
      *listener << "interface was " << method_call->GetInterface();
      return false;
    }

    if (method_call->GetMember() != vm_tools::concierge::kStopAllVmsMethod) {
      *listener << "method name was " << method_call->GetMember();
      return false;
    }

    return true;
  }

  void DescribeTo(::std::ostream* os) const override {
    *os << "StopAllVms method call";
  }

  void DescribeNegationTo(::std::ostream* os) const override {
    *os << "non-StopAllVms method call";
  }
};

inline testing::Matcher<dbus::MethodCall*> StopAllVmsMethod() {
  return MakeMatcher(new StopAllVmsMethodMatcher());
}

// Browser processes get correctly terminated.
TEST_F(SessionManagerProcessTest, CleanupBrowser) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(false);
  EXPECT_CALL(*job, Kill(SIGTERM, _)).Times(1);
  EXPECT_CALL(*job, AbortAndKillAll(_)).Times(1);
  job->RunInBackground();
  manager_->test_api().CleanupChildrenBeforeExit();
}

// Gracefully shut down while the browser is running.
TEST_F(SessionManagerProcessTest, BrowserRunningShutdown) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(false);

  ExpectLivenessChecking();
  ExpectShutdown();

  // Expect the job to be killed.
  EXPECT_CALL(*job, Kill(SIGTERM, _)).Times(1);
  EXPECT_CALL(*job, AbortAndKillAll(_)).Times(1);

  brillo::MessageLoop::current()->PostTask(
      FROM_HERE,
      base::Bind(&SessionManagerService::RunBrowser, manager_.get()));

  brillo::MessageLoop::current()->PostTask(
      FROM_HERE,
      base::Bind(&SessionManagerService::ScheduleShutdown, manager_.get()));

  ForceRunLoop();
}

// If the browser exits and asks to stop, the session manager
// should not restart it.
TEST_F(SessionManagerProcessTest, ChildExitFlagFileStop) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  manager_->test_api().set_exit_on_child_done(true);  // or it'll run forever.
  ExpectLivenessChecking();

  EXPECT_CALL(*job, KillEverything(SIGKILL, _)).Times(AnyNumber());
  EXPECT_CALL(*job, ShouldStop()).WillOnce(Return(false));
  EXPECT_CALL(metrics_,
              SendSessionExitType(LoginMetrics::SessionExitType::NORMAL_EXIT))
      .Times(1);
  // Browser shutdown time is track when browser request to stop.
  EXPECT_CALL(metrics_, SendBrowserShutdownTime(_)).Times(1);
  job->set_should_run(false);

  EXPECT_CALL(*session_manager_impl_, ShouldEndSession(_))
      .WillOnce(Return(false));

  SimpleRunManager();
}

// A child that exits with a signal should get re-run.
TEST_F(SessionManagerProcessTest, BadExitChildOnSignal) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  ExpectLivenessChecking();
  ExpectOneJobReRun(job, PackSignal(SIGILL));
  SimpleRunManager();
}

// A child that exits badly should get re-run.
TEST_F(SessionManagerProcessTest, BadExitChild) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  ExpectLivenessChecking();
  ExpectOneJobReRun(job, PackSignal(kExit));
  SimpleRunManager();
}

// A child that exits cleanly should get re-run.
TEST_F(SessionManagerProcessTest, CleanExitChild) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  ExpectLivenessChecking();
  ExpectOneJobReRun(job, PackSignal(0));
  SimpleRunManager();
}

// If the browser exits while the screen is locked, the session manager
// should exit.
TEST_F(SessionManagerProcessTest, LockedExit) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  ExpectLivenessChecking();

  EXPECT_CALL(*job, KillEverything(SIGKILL, _)).Times(AnyNumber());
  EXPECT_CALL(*job, ShouldStop()).Times(0);

  EXPECT_CALL(*session_manager_impl_, ShouldEndSession(_))
      .WillOnce(Return(true));
  EXPECT_CALL(metrics_,
              SendSessionExitType(LoginMetrics::SessionExitType::NORMAL_EXIT))
      .Times(1);
  // Browser shutdown time is not tracked if browser does not request stop.
  EXPECT_CALL(metrics_, SendBrowserShutdownTime(_)).Times(0);

  SimpleRunManager();
}

// Liveness checking should be started and stopped along with the browser.
TEST_F(SessionManagerProcessTest, LivenessCheckingStartStop) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  {
    Sequence start_stop;
    EXPECT_CALL(*liveness_checker_, Start()).Times(2);
    EXPECT_CALL(*liveness_checker_, Stop()).Times(AtLeast(1));
  }
  EXPECT_CALL(metrics_, SendBrowserShutdownTime(_)).Times(0);
  ExpectOneJobReRun(job, PackSignal(0));
  SimpleRunManager();
}

// If the child indicates it should be stopped, the session manager must honor.
TEST_F(SessionManagerProcessTest, MustStopChild) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  ExpectLivenessChecking();
  EXPECT_CALL(*job, KillEverything(SIGKILL, _)).Times(AnyNumber());
  // ShouldStop returning true indicates a login crash loop.
  EXPECT_CALL(*job, ShouldStop()).WillOnce(Return(true));
  EXPECT_CALL(*session_manager_impl_, ShouldEndSession(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(metrics_, SendSessionExitType(
                            LoginMetrics::SessionExitType::LOGIN_CRASH_LOOP))
      .Times(1);
  // Browser shutdown time is not tracked if browser does not request stop.
  EXPECT_CALL(metrics_, SendBrowserShutdownTime(_)).Times(0);

  SimpleRunManager();
}

TEST_F(SessionManagerProcessTest, TestWipeOnBadState) {
  CreateMockJobAndInitManager(true);

  EXPECT_CALL(*session_manager_impl_, Initialize()).WillOnce(Return(false));

  // Expect Powerwash to be triggered.
  EXPECT_CALL(*session_manager_impl_, InitiateDeviceWipe(_)).Times(1);
  EXPECT_CALL(*session_manager_impl_, Finalize()).Times(1);

  ASSERT_FALSE(manager_->test_api().InitializeImpl());
  ASSERT_EQ(SessionManagerService::MUST_WIPE_DEVICE, manager_->exit_code());
}

// When aborting the browser, the session manager should write the killed pid.
TEST_F(SessionManagerProcessTest, TestAbortedBrowserPidWritten) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(false);
  EXPECT_CALL(*job, KillEverything(SIGKILL, _)).Times(AnyNumber());
  ASSERT_TRUE(job->RunInBackground());

  manager_->AbortBrowserForHang();
  ASSERT_TRUE(base::PathExists(aborted_browser_pid_path_));
  std::string read_pid_str;
  ASSERT_TRUE(base::ReadFileToString(aborted_browser_pid_path_, &read_pid_str));
  int read_pid = atoi(read_pid_str.c_str());
  EXPECT_EQ(kFakePid, read_pid);
}

// When the vm_concierge service is running, stop all vms when the session ends.
TEST_F(SessionManagerProcessTest, StopAllVms) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(true);
  scoped_refptr<dbus::MockObjectProxy> vm_concierge_proxy(
      new dbus::MockObjectProxy(nullptr, "", dbus::ObjectPath("/fake/vm")));
  manager_->test_api().set_vm_concierge_proxy(vm_concierge_proxy.get());
  manager_->test_api().set_vm_concierge_available(true);

  EXPECT_CALL(*vm_concierge_proxy.get(), DoCallMethod(StopAllVmsMethod(), _, _))
      .Times(AtLeast(1));

  ExpectLivenessChecking();
  ExpectOneJobReRun(job, PackSignal(0));

  SimpleRunManager();
}

TEST_F(SessionManagerProcessTest, SetBrowserDataMigrationArgsForUser) {
  FakeBrowserJob* job = CreateMockJobAndInitManager(false);

  const std::string userhash = "1234abcd";
  EXPECT_CALL(*job, SetBrowserDataMigrationArgsForUser(userhash)).Times(1);
  manager_->SetBrowserDataMigrationArgsForUser(userhash);
}

TEST_F(SessionManagerProcessTest, ClearBrowserDataMigrationArgs) {
  // Check that |SessionManager::RunBrowser()| calls
  // |ClearBrowserDataMigrationArgs()| after fork/exec if browser data migration
  // args were set, ensuring that migration is attempted only once.
  FakeBrowserJob* job = CreateMockJobAndInitManager(false);
  const std::string userhash = "1234abcd";
  manager_->SetBrowserDataMigrationArgsForUser(userhash);

  EXPECT_CALL(*job, ClearBrowserDataMigrationArgs());

  manager_->RunBrowser();
}

}  // namespace login_manager
