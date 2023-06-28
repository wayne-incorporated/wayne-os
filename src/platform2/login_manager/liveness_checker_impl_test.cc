// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/liveness_checker_impl.h"

#include <memory>
#include <utility>

#include <base/memory/ref_counted.h>
#include <base/time/time.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <dbus/message.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

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
    checker_.reset(new LivenessCheckerImpl(manager_.get(), object_proxy_.get(),
                                           true, TimeDelta::FromSeconds(10)));
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

 private:
  void Respond(dbus::MethodCall* method_call,
               int timeout_ms,
               dbus::ObjectProxy::ResponseCallback* callback) {
    std::move(*callback).Run(dbus::Response::CreateEmpty().get());
  }
};

TEST_F(LivenessCheckerImplTest, CheckAndSendOutstandingPing) {
  ExpectUnAckedLivenessPing();
  EXPECT_CALL(*manager_.get(), AbortBrowserForHang()).Times(1);
  checker_->CheckAndSendLivenessPing(TimeDelta());
  fake_loop_.Run();  // Runs until the message loop is empty.
}

TEST_F(LivenessCheckerImplTest, CheckAndSendAckedThenOutstandingPing) {
  ExpectLivenessPingResponsePing();
  EXPECT_CALL(*manager_.get(), AbortBrowserForHang()).Times(1);
  checker_->CheckAndSendLivenessPing(TimeDelta());
  fake_loop_.Run();  // Runs until the message loop is empty.
}

TEST_F(LivenessCheckerImplTest, CheckAndSendAckedThenOutstandingPingNeutered) {
  checker_.reset(new LivenessCheckerImpl(manager_.get(), object_proxy_.get(),
                                         false,  // Disable aborting
                                         TimeDelta::FromSeconds(10)));
  ExpectPingResponsePingCheckPingAndQuit();
  // Expect _no_ browser abort!
  checker_->CheckAndSendLivenessPing(TimeDelta::FromSeconds(1));
  fake_loop_.Run();  // Runs until the message loop is empty.
}

TEST_F(LivenessCheckerImplTest, StartStop) {
  checker_->Start();
  EXPECT_TRUE(checker_->IsRunning());
  checker_->Stop();  // Should cancel ping, so...
  EXPECT_FALSE(checker_->IsRunning());
}

}  // namespace login_manager
