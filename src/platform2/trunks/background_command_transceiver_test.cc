// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/background_command_transceiver.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <base/threading/platform_thread.h>
#include <base/threading/thread.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/command_transceiver.h"
#include "trunks/mock_command_transceiver.h"

using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::WithArgs;

namespace {

const char kTestThreadName[] = "test_thread";

std::string GetThreadName() {
  return std::string(base::PlatformThread::GetName());
}

void GetThreadNameAndCall(
    trunks::CommandTransceiver::ResponseCallback callback) {
  std::move(callback).Run(GetThreadName());
}

void Assign(std::string* to, const std::string& from) {
  *to = from;
}

void SendCommandAndWaitAndAssign(trunks::CommandTransceiver* transceiver,
                                 std::string* output) {
  *output = transceiver->SendCommandAndWait("test");
}

}  // namespace

namespace trunks {

class BackgroundTransceiverTest : public testing::Test {
 public:
  BackgroundTransceiverTest() : test_thread_(kTestThreadName) {
    EXPECT_CALL(next_transceiver_, SendCommand(_, _))
        .WillRepeatedly(WithArgs<1>(Invoke(GetThreadNameAndCall)));
    EXPECT_CALL(next_transceiver_, SendCommandAndWait(_))
        .WillRepeatedly(InvokeWithoutArgs(GetThreadName));
    CHECK(test_thread_.Start());
  }

  ~BackgroundTransceiverTest() override {}

 protected:
  base::test::TaskEnvironment task_environment_{
    base::test::TaskEnvironment::MainThreadType::IO};
  base::Thread test_thread_;
  MockCommandTransceiver next_transceiver_;
};

TEST_F(BackgroundTransceiverTest, Asynchronous) {
  trunks::BackgroundCommandTransceiver background_transceiver(
      &next_transceiver_, test_thread_.task_runner());
  std::string output = "not_assigned";
  background_transceiver.SendCommand("test", base::BindOnce(Assign, &output));
  do {
    base::RunLoop run_loop;
    run_loop.RunUntilIdle();
  } while (output == "not_assigned");
  // The call to our mock should have happened on the background thread.
  EXPECT_EQ(std::string(kTestThreadName), output);
  test_thread_.Stop();
}

TEST_F(BackgroundTransceiverTest, Synchronous) {
  trunks::BackgroundCommandTransceiver background_transceiver(
      &next_transceiver_, test_thread_.task_runner());
  std::string output = "not_assigned";
  // Post a synchronous call to be run when we start pumping the loop.
  task_environment_.GetMainThreadTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(SendCommandAndWaitAndAssign,
                                &background_transceiver, &output));
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();
  // The call to our mock should have happened on the background thread.
  EXPECT_EQ(std::string("test_thread"), output);
  test_thread_.Stop();
}

}  // namespace trunks
