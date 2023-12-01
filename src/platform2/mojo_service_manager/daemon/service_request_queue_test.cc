// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/test/bind.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "mojo_service_manager/daemon/service_request_queue.h"
#include "mojo_service_manager/testing/mojo_test_environment.h"

namespace chromeos {
namespace mojo_service_manager {
namespace {

class ServiceRequestQueueTest : public ::testing::Test {
 protected:
  MojoTaskEnvironment env_{base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  ServiceRequestQueue queue_{"FakeServiceName"};
};

TEST_F(ServiceRequestQueueTest, PushAndTake) {
  queue_.Push(mojom::ProcessIdentity::New(), std::nullopt,
              mojo::ScopedMessagePipeHandle{});
  queue_.Push(mojom::ProcessIdentity::New(), base::Seconds(0),
              mojo::ScopedMessagePipeHandle{});
  queue_.Push(mojom::ProcessIdentity::New(), base::Seconds(10),
              mojo::ScopedMessagePipeHandle{});
  EXPECT_EQ(queue_.TakeAllRequests().size(), 3);
  // The queue is now empty.
  EXPECT_TRUE(queue_.TakeAllRequests().empty());
}

TEST_F(ServiceRequestQueueTest, Timeout) {
  queue_.Push(mojom::ProcessIdentity::New(), std::nullopt,
              mojo::ScopedMessagePipeHandle{});
  // This must use a valid pipe.
  mojo::Remote<mojom::ServiceObserver> remote;
  queue_.Push(mojom::ProcessIdentity::New(), base::Seconds(5),
              remote.BindNewPipeAndPassReceiver().PassPipe());
  queue_.Push(mojom::ProcessIdentity::New(), base::Seconds(10),
              mojo::ScopedMessagePipeHandle{});
  // Pop the one with 5 seconds timeout.
  env_.FastForwardBy(base::Seconds(5));
  EXPECT_EQ(queue_.TakeAllRequests().size(), 2);
}

TEST_F(ServiceRequestQueueTest, MojoError) {
  mojo::Remote<mojom::ServiceObserver> remote;
  queue_.Push(mojom::ProcessIdentity::New(), base::Seconds(5),
              remote.BindNewPipeAndPassReceiver().PassPipe());
  base::RunLoop run_loop;
  remote.set_disconnect_with_reason_handler(base::BindLambdaForTesting(
      [&](uint32_t error, const std::string& message) {
        EXPECT_EQ(error, static_cast<uint32_t>(mojom::ErrorCode::kTimeout));
        run_loop.Quit();
      }));
  run_loop.Run();
}

}  // namespace
}  // namespace mojo_service_manager
}  // namespace chromeos
