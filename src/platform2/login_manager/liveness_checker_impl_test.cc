// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/liveness_checker_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/time/time.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <brillo/syslog_logging.h>
#include <dbus/message.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "login_manager/mock_metrics.h"
#include "login_manager/mock_process_manager_service.h"

using ::base::TimeDelta;
using ::testing::_;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::StrictMock;

namespace login_manager {

class LivenessCheckerImplTest : public ::testing::Test {
 public:
  LivenessCheckerImplTest() {}
  LivenessCheckerImplTest(const LivenessCheckerImplTest&) = delete;
  LivenessCheckerImplTest& operator=(const LivenessCheckerImplTest&) = delete;

  ~LivenessCheckerImplTest() override {}

  void SetUp() override {
    fake_loop_.SetAsCurrent();
    manager_.reset(new StrictMock<MockProcessManagerService>);
    object_proxy_ =
        new dbus::MockObjectProxy(nullptr, "", dbus::ObjectPath("/fake/path"));

    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());

    metrics_.reset(new MockMetrics());

    checker_.reset(new LivenessCheckerImpl(manager_.get(), object_proxy_.get(),
                                           true, base::Seconds(10),
                                           metrics_.get()));
    base::FilePath fake_proc_path(tmpdir_.GetPath());
    checker_->SetProcForTests(std::move(fake_proc_path));
  }

  void ExpectUnAckedLivenessPing() {
    EXPECT_CALL(*object_proxy_.get(), DoCallMethod(_, _, _)).Times(1);
  }

  // Expect two pings, the first with a response.
  void ExpectLivenessPingResponsePing() {
    EXPECT_CALL(*object_proxy_.get(), DoCallMethod(_, _, _))
        .WillOnce(Invoke(this, &LivenessCheckerImplTest::Respond))
        .WillOnce(Return());
  }

  // Expect three runs through CheckAndSendLivenessPing():
  // 1) No ping has been sent before, so expect initial ping and ACK it.
  // 2) Last ping was ACK'd, so expect a no-op during this run.
  // 3) Caller should expect action during this run; Quit after it.
  void ExpectPingResponsePingCheckPingAndQuit() {
    EXPECT_CALL(*object_proxy_.get(), DoCallMethod(_, _, _))
        .WillOnce(Invoke(this, &LivenessCheckerImplTest::Respond))
        .WillOnce(Return())
        .WillOnce(InvokeWithoutArgs(brillo::MessageLoop::current(),
                                    &brillo::MessageLoop::BreakLoop));
  }

  brillo::FakeMessageLoop fake_loop_{nullptr};
  scoped_refptr<dbus::MockObjectProxy> object_proxy_;
  std::unique_ptr<StrictMock<MockProcessManagerService>> manager_;

  std::unique_ptr<LivenessCheckerImpl> checker_;

  base::ScopedTempDir tmpdir_;
  std::unique_ptr<MockMetrics> metrics_;

 private:
  void Respond(dbus::MethodCall* method_call,
               int timeout_ms,
               dbus::ObjectProxy::ResponseCallback* callback) {
    std::move(*callback).Run(dbus::Response::CreateEmpty().get());
  }
};

TEST_F(LivenessCheckerImplTest, CheckAndSendOutstandingPing) {
  ExpectUnAckedLivenessPing();

  // Expects one failure for the un-acked ping.
  EXPECT_CALL(*metrics_, SendLivenessPingResult(/*succeess=*/false)).Times(1);

  EXPECT_CALL(*manager_.get(), AbortBrowserForHang()).Times(1);
  EXPECT_CALL(*manager_.get(), GetBrowserPid())
      .WillRepeatedly(Return(std::nullopt));
  checker_->CheckAndSendLivenessPing(TimeDelta());
  fake_loop_.Run();  // Runs until the message loop is empty.
}

TEST_F(LivenessCheckerImplTest, CheckAndSendAckedThenOutstandingPing) {
  ExpectLivenessPingResponsePing();

  // Expects one success for acked ping and one failure for the un-acked one.
  EXPECT_CALL(*metrics_, SendLivenessPingResult(/*succeess=*/true)).Times(1);
  EXPECT_CALL(*metrics_, SendLivenessPingResult(/*succeess=*/false)).Times(1);

  EXPECT_CALL(*manager_.get(), AbortBrowserForHang()).Times(1);
  EXPECT_CALL(*manager_.get(), GetBrowserPid())
      .WillRepeatedly(Return(std::nullopt));
  checker_->CheckAndSendLivenessPing(TimeDelta());
  fake_loop_.Run();  // Runs until the message loop is empty.
}

TEST_F(LivenessCheckerImplTest, CheckAndSendAckedThenOutstandingPingNeutered) {
  checker_.reset(new LivenessCheckerImpl(manager_.get(), object_proxy_.get(),
                                         false,  // Disable aborting
                                         base::Seconds(10), metrics_.get()));
  base::FilePath fake_proc_path(tmpdir_.GetPath());
  checker_->SetProcForTests(std::move(fake_proc_path));

  ExpectPingResponsePingCheckPingAndQuit();

  // Expects one success for acked ping and one failure for the un-acked one.
  EXPECT_CALL(*metrics_, SendLivenessPingResult(/*succeess=*/true)).Times(1);
  EXPECT_CALL(*metrics_, SendLivenessPingResult(/*succeess=*/false)).Times(1);

  // Expect _no_ browser abort!
  EXPECT_CALL(*manager_.get(), AbortBrowserForHang()).Times(0);
  // But we still record the UMA.
  EXPECT_CALL(*manager_.get(), GetBrowserPid())
      .WillRepeatedly(Return(std::nullopt));
  checker_->CheckAndSendLivenessPing(base::Seconds(1));
  fake_loop_.Run();  // Runs until the message loop is empty.
}

TEST_F(LivenessCheckerImplTest, StartStop) {
  checker_->Start();
  EXPECT_TRUE(checker_->IsRunning());
  checker_->Stop();  // Should cancel ping, so...
  EXPECT_FALSE(checker_->IsRunning());
}

struct TestFileAndStatus {
  const char* const test_name;
  const char* const file_name;
  LoginMetrics::BrowserState expected_state;
  const char* const expected_log_message;
};

const TestFileAndStatus kTestFilesAndStatuses[] = {
    {"Running", "TEST_STATUS_RUNNING", LoginMetrics::BrowserState::kRunning,
     nullptr},
    {"Sleeping", "TEST_STATUS_SLEEPING", LoginMetrics::BrowserState::kSleeping,
     nullptr},
    {"Stopped", "TEST_STATUS_STOPPED",
     LoginMetrics::BrowserState::kTracedOrStopped, nullptr},
    {"UninterruptibleWait", "TEST_STATUS_UNINTERRUPTIBLE_WAIT",
     LoginMetrics::BrowserState::kUninterruptibleWait, nullptr},
    {"Zombie", "TEST_STATUS_ZOMBIE", LoginMetrics::BrowserState::kZombie,
     nullptr},
    {"UnknownState", "TEST_STATUS_UNKNOWN_STATE",
     LoginMetrics::BrowserState::kUnknown, "Unknown browser state X"},
    {"MissingStateLine", "TEST_STATUS_MISSING_STATE",
     LoginMetrics::BrowserState::kErrorGettingState,
     "Could not find '\\nState:\\t'"},
    {"StateAtEnd", "TEST_STATUS_STATE_IS_LAST_CHARACTER",
     LoginMetrics::BrowserState::kErrorGettingState,
     "State:\\t at very end of file"},
    {"MissingStatusFile", nullptr,
     LoginMetrics::BrowserState::kErrorGettingState, "Could not open "}};

class LivenessCheckerImplParamTest
    : public LivenessCheckerImplTest,
      public testing::WithParamInterface<TestFileAndStatus> {};

TEST_P(LivenessCheckerImplParamTest, BrowserStatusToUMA) {
  brillo::InitLog(brillo::kLogToStderr);
  if (GetParam().file_name != nullptr) {
    base::FilePath fake_status_path = tmpdir_.GetPath().Append("123");
    base::File::Error error;
    ASSERT_TRUE(base::CreateDirectoryAndGetError(fake_status_path, &error))
        << base::File::ErrorToString(error);
    base::FilePath fake_status_file_name = fake_status_path.Append("status");
    base::FilePath test_data_file_name =
        base::FilePath("testdata").Append(GetParam().file_name);
    ASSERT_TRUE(base::CopyFile(test_data_file_name, fake_status_file_name))
        << "Could not copy " << test_data_file_name.value() << " to "
        << fake_status_file_name.value();
  }

  if (GetParam().expected_log_message != nullptr) {
    brillo::ClearLog();
    brillo::LogToString(true);
  }

  ExpectUnAckedLivenessPing();
  EXPECT_CALL(*manager_.get(), AbortBrowserForHang()).Times(1);
  EXPECT_CALL(*manager_.get(), GetBrowserPid()).WillRepeatedly(Return(123));
  checker_->CheckAndSendLivenessPing(TimeDelta());
  fake_loop_.Run();  // Runs until the message loop is empty.

  if (GetParam().expected_log_message != nullptr) {
    EXPECT_TRUE(brillo::FindLog(GetParam().expected_log_message))
        << "Did not find '" << GetParam().expected_log_message << "' in logs";
    brillo::LogToString(false);
    brillo::ClearLog();
  }
}

INSTANTIATE_TEST_SUITE_P(
    LivenessChecker,
    LivenessCheckerImplParamTest,
    testing::ValuesIn(kTestFilesAndStatuses),
    [](const ::testing::TestParamInfo<LivenessCheckerImplParamTest::ParamType>&
           info) { return std::string(info.param.test_name); });

}  // namespace login_manager
