// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/vtpm_service.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <base/threading/thread.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::brillo::dbus_utils::MockDBusMethodResponse;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Matcher;
using ::testing::MatchesRegex;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::Unused;

namespace vtpm {

namespace {

constexpr char kTestMessage[] = "test message";

class EchoCommand : public Command {
 public:
  void Run(const std::string& command,
           CommandResponseCallback callback) override {
    std::move(callback).Run(command);
  }
};

class EchoCommandWithThread : public Command {
 public:
  EchoCommandWithThread() {
    worker_thread_.reset(new base::Thread("EchoCommandWithThreadWorker"));
  }
  ~EchoCommandWithThread() override { worker_thread_->Stop(); }
  void Run(const std::string& command,
           CommandResponseCallback callback) override {
    worker_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](const std::string& command, CommandResponseCallback callback) {
              std::move(callback).Run(command);
            },
            command, std::move(callback)));
  }
  void Start() {
    worker_thread_->StartWithOptions(
        base::Thread::Options(base::MessagePumpType::IO, 0));
  }

 private:
  std::unique_ptr<base::Thread> worker_thread_;
};

class EchoCommandSelector : public Command {
 public:
  void SetIsThreaded(bool is_threaded) { is_threaded_ = is_threaded; }
  void Run(const std::string& command,
           CommandResponseCallback callback) override {
    if (is_threaded_) {
      threaded_echo_command_.Start();
      threaded_echo_command_.Run(command, std::move(callback));
    } else {
      echo_command_.Run(command, std::move(callback));
    }
  }

 private:
  bool is_threaded_ = false;
  EchoCommand echo_command_;
  EchoCommandWithThread threaded_echo_command_;
};

}  // namespace

class VtpmServiceTest : public ::testing::Test {
 public:
  // No setup needed for this test.
 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;

  EchoCommandSelector selector_;
  VtpmService service_{&selector_};
};

namespace {

TEST_F(VtpmServiceTest, GetResponseWorkerThread) {
  selector_.SetIsThreaded(true);
  base::test::TestFuture<const SendCommandResponse&> future;
  std::unique_ptr<MockDBusMethodResponse<SendCommandResponse>> response(
      new MockDBusMethodResponse<SendCommandResponse>());
  response->set_return_callback(future.GetCallback());
  SendCommandRequest request;
  request.set_command(kTestMessage);
  service_.SendCommand(std::move(response), request);
  EXPECT_EQ(future.Get().response(), kTestMessage);
}

TEST_F(VtpmServiceTest, GetResponseNoWorkerThread) {
  selector_.SetIsThreaded(false);
  base::test::TestFuture<const SendCommandResponse&> future;
  std::unique_ptr<MockDBusMethodResponse<SendCommandResponse>> response(
      new MockDBusMethodResponse<SendCommandResponse>());
  response->set_return_callback(future.GetCallback());
  SendCommandRequest request;
  request.set_command(kTestMessage);
  service_.SendCommand(std::move(response), request);
  EXPECT_EQ(future.Get().response(), kTestMessage);
}

}  // namespace
}  // namespace vtpm
