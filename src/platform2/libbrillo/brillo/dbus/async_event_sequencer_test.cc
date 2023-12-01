// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/dbus/async_event_sequencer.h>

#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace brillo {

namespace dbus_utils {

namespace {

const char kTestInterface[] = "org.test.if";
const char kTestMethod1[] = "TestMethod1";
const char kTestMethod2[] = "TestMethod2";

}  // namespace

class AsyncEventSequencerTest : public ::testing::Test {
 public:
  MOCK_METHOD(void, HandleCompletion, (bool));

  void SetUp() {
    aec_ = new AsyncEventSequencer();
    cb_ = base::BindOnce(&AsyncEventSequencerTest::HandleCompletion,
                         base::Unretained(this));
  }

  scoped_refptr<AsyncEventSequencer> aec_;
  AsyncEventSequencer::CompletionAction cb_;
};

TEST_F(AsyncEventSequencerTest, WaitForCompletionActions) {
  auto finished_handler = aec_->GetHandler("handler failed", false);
  std::move(finished_handler).Run(true);
  EXPECT_CALL(*this, HandleCompletion(true)).Times(1);
  aec_->OnAllTasksCompletedCall(std::move(cb_));
}

TEST_F(AsyncEventSequencerTest, MultiInitActionsSucceed) {
  auto finished_handler1 = aec_->GetHandler("handler failed", false);
  auto finished_handler2 = aec_->GetHandler("handler failed", false);
  aec_->OnAllTasksCompletedCall(std::move(cb_));
  std::move(finished_handler1).Run(true);
  EXPECT_CALL(*this, HandleCompletion(true)).Times(1);
  std::move(finished_handler2).Run(true);
}

TEST_F(AsyncEventSequencerTest, SomeInitActionsFail) {
  auto finished_handler1 = aec_->GetHandler("handler failed", false);
  auto finished_handler2 = aec_->GetHandler("handler failed", false);
  aec_->OnAllTasksCompletedCall(std::move(cb_));
  std::move(finished_handler1).Run(false);
  EXPECT_CALL(*this, HandleCompletion(false)).Times(1);
  std::move(finished_handler2).Run(true);
}

TEST_F(AsyncEventSequencerTest, MultiDBusActionsSucceed) {
  auto handler1 = aec_->GetExportHandler(kTestInterface, kTestMethod1,
                                         "method export failed", false);
  auto handler2 = aec_->GetExportHandler(kTestInterface, kTestMethod2,
                                         "method export failed", false);
  aec_->OnAllTasksCompletedCall(std::move(cb_));
  std::move(handler1).Run(kTestInterface, kTestMethod1, true);
  EXPECT_CALL(*this, HandleCompletion(true)).Times(1);
  std::move(handler2).Run(kTestInterface, kTestMethod2, true);
}

TEST_F(AsyncEventSequencerTest, SomeDBusActionsFail) {
  auto handler1 = aec_->GetExportHandler(kTestInterface, kTestMethod1,
                                         "method export failed", false);
  auto handler2 = aec_->GetExportHandler(kTestInterface, kTestMethod2,
                                         "method export failed", false);
  aec_->OnAllTasksCompletedCall(std::move(cb_));
  std::move(handler1).Run(kTestInterface, kTestMethod1, true);
  EXPECT_CALL(*this, HandleCompletion(false)).Times(1);
  std::move(handler2).Run(kTestInterface, kTestMethod2, false);
}

TEST_F(AsyncEventSequencerTest, MixedActions) {
  auto handler1 = aec_->GetExportHandler(kTestInterface, kTestMethod1,
                                         "method export failed", false);
  auto handler2 = aec_->GetHandler("handler failed", false);
  aec_->OnAllTasksCompletedCall(std::move(cb_));
  std::move(handler1).Run(kTestInterface, kTestMethod1, true);
  EXPECT_CALL(*this, HandleCompletion(true)).Times(1);
  std::move(handler2).Run(true);
}

}  // namespace dbus_utils

}  // namespace brillo
