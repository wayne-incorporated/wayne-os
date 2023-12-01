// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/grpc_completion_queue_dispatcher.h"

#include <list>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/task/task_runner.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <grpcpp/alarm.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

#include "brillo/grpc/time_util.h"

namespace brillo {

namespace {

// Allows testing if a callback has been invoked, and the value of the
// grpc-specific |ok| bool parameter.
class TagAvailableCalledTester {
 public:
  TagAvailableCalledTester() = default;
  TagAvailableCalledTester(const TagAvailableCalledTester&) = delete;
  TagAvailableCalledTester& operator=(const TagAvailableCalledTester&) = delete;

  ~TagAvailableCalledTester() = default;

  GrpcCompletionQueueDispatcher::TagAvailableCallback
  GetTagAvailableCallback() {
    return base::BindOnce(&TagAvailableCalledTester::Callback,
                          base::Unretained(this));
  }

  // Bind this to a RegisterTag call of the
  // |GrpcCompletionQueueDispatcher|. Will check that it is invoked at
  // most once, remember the value of |ok|, and call the closure passed to
  // |CallWhenInvoked|, if any.
  void Callback(bool ok) {
    CHECK(!has_been_called_);
    has_been_called_ = true;
    value_of_ok_ = ok;

    std::list<base::OnceClosure> callbacks_temp;
    callbacks_temp.swap(call_when_invoked_);
    for (auto& callback : callbacks_temp)
      std::move(callback).Run();
  }

  // Register |call_when_invoked| to be called when |Callback| is called.
  void CallWhenInvoked(base::OnceClosure call_when_invoked) {
    call_when_invoked_.push_back(std::move(call_when_invoked));
  }

  // Returns true if |Callback| has been called.
  bool has_been_called() const { return has_been_called_; }

  // Only call if |has_been_called()| is returning true. Returns the value of
  // |ok| passed to |Callback|.
  bool value_of_ok() const {
    CHECK(has_been_called());
    return value_of_ok_;
  }

 private:
  bool has_been_called_ = false;
  bool value_of_ok_ = false;
  std::list<base::OnceClosure> call_when_invoked_;
};

// Allows testing if an object (owned by callback) has been destroyed. Also
// tests that this is destroyed on the same message loop it has been
// instantiated on.
class ObjectDestroyedTester {
 public:
  // Will set |*has_been_destroyed| to true when this instance is being
  // destroyed.
  explicit ObjectDestroyedTester(bool* has_been_destroyed)
      : expected_task_runner_(
            base::SingleThreadTaskRunner::GetCurrentDefault()),
        has_been_destroyed_(has_been_destroyed) {
    *has_been_destroyed_ = false;
  }
  ObjectDestroyedTester(const ObjectDestroyedTester&) = delete;
  ObjectDestroyedTester& operator=(const ObjectDestroyedTester&) = delete;

  ~ObjectDestroyedTester() {
    EXPECT_TRUE(expected_task_runner_->BelongsToCurrentThread());
    *has_been_destroyed_ = true;
  }

 private:
  const scoped_refptr<base::SingleThreadTaskRunner> expected_task_runner_;
  bool* const has_been_destroyed_;
};

// An adapter to be able to give a Callback to
// |GrpcCompletionQueueDispatcher::RegisterTag| which owns an
// |ObjectDestroyedTester|.
void ObjectDestroyedTesterAdapter(
    TagAvailableCalledTester* tag_available_called_tester,
    std::unique_ptr<ObjectDestroyedTester> object_destroyed_tester,
    bool ok) {
  tag_available_called_tester->Callback(ok);
}

}  // namespace

class GrpcCompletionQueueDispatcherTest : public ::testing::Test {
 public:
  GrpcCompletionQueueDispatcherTest()
      : dispatcher_(&completion_queue_,
                    base::SingleThreadTaskRunner::GetCurrentDefault()) {
    dispatcher_.Start();
  }
  GrpcCompletionQueueDispatcherTest(const GrpcCompletionQueueDispatcherTest&) =
      delete;
  GrpcCompletionQueueDispatcherTest& operator=(
      const GrpcCompletionQueueDispatcherTest&) = delete;

  ~GrpcCompletionQueueDispatcherTest() override = default;

 protected:
  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  grpc::CompletionQueue completion_queue_;

  // The dispatcher under test.
  GrpcCompletionQueueDispatcher dispatcher_;

  // Note: This can't be |const void*| because gRPC functions expect |void*|.
  void* const kTag = reinterpret_cast<void*>(1);

  void ShutdownDispatcher() {
    base::RunLoop run_loop;
    dispatcher_.Shutdown(run_loop.QuitClosure());
    run_loop.Run();
  }
};

// Start and shutdown a dispatcher, with no tags posted to the underlying
// CompletionQueue.
TEST_F(GrpcCompletionQueueDispatcherTest, StartAndShutdownEmpty) {
  ShutdownDispatcher();
}

// Register a tag that is not passed to the CompletionQueue. Check that the
// callback is never called, but that it is properly destroyed. This also
// demonstrates that instances passed to the callback using base::Passed are
// properly destroyed in this case.
TEST_F(GrpcCompletionQueueDispatcherTest, TagNeverAvailable) {
  bool object_has_been_destroyed = false;
  auto object_destroyed_tester =
      std::make_unique<ObjectDestroyedTester>(&object_has_been_destroyed);

  TagAvailableCalledTester tag_available_called_tester;
  dispatcher_.RegisterTag(nullptr,
                          base::BindOnce(&ObjectDestroyedTesterAdapter,
                                         &tag_available_called_tester,
                                         std::move(object_destroyed_tester)));

  ShutdownDispatcher();

  EXPECT_FALSE(tag_available_called_tester.has_been_called());
  EXPECT_TRUE(object_has_been_destroyed);
}

// Register a tag that becomes available with |ok=true|. Verify that the
// registered callback is called with |ok=true|.
TEST_F(GrpcCompletionQueueDispatcherTest,
       CompletionQueueTagAvailableWithOkTrue) {
  base::RunLoop run_loop;
  TagAvailableCalledTester tag_available_called_tester;
  tag_available_called_tester.CallWhenInvoked(run_loop.QuitClosure());

  dispatcher_.RegisterTag(
      kTag, tag_available_called_tester.GetTagAvailableCallback());

  grpc::Alarm alarm(&completion_queue_,
                    GprTimespecWithDeltaFromNow(base::Milliseconds(1)), kTag);
  run_loop.Run();

  EXPECT_TRUE(tag_available_called_tester.has_been_called());
  EXPECT_TRUE(tag_available_called_tester.value_of_ok());

  ShutdownDispatcher();
}

// Register a tag that becomes available with |ok=false|. Verify that the
// regitered callback is called with |ok=false|.
TEST_F(GrpcCompletionQueueDispatcherTest,
       CompletionQueueTagAvailableWithOkFalse) {
  base::RunLoop run_loop;
  TagAvailableCalledTester tag_available_called_tester;
  tag_available_called_tester.CallWhenInvoked(run_loop.QuitClosure());

  dispatcher_.RegisterTag(
      kTag, tag_available_called_tester.GetTagAvailableCallback());

  grpc::Alarm alarm(&completion_queue_,
                    GprTimespecWithDeltaFromNow(base::Hours(24)), kTag);
  alarm.Cancel();
  run_loop.Run();

  EXPECT_TRUE(tag_available_called_tester.has_been_called());
  EXPECT_FALSE(tag_available_called_tester.value_of_ok());

  ShutdownDispatcher();
}

// Re-register a tag that becomes available in the context of the tag's
// callback.
TEST_F(GrpcCompletionQueueDispatcherTest, ReregisterTag) {
  base::RunLoop run_loop_1;
  TagAvailableCalledTester tag_available_called_tester_1;
  base::RunLoop run_loop_2;
  TagAvailableCalledTester tag_available_called_tester_2;

  dispatcher_.RegisterTag(
      kTag, tag_available_called_tester_1.GetTagAvailableCallback());
  auto reregister_tag_callback =
      base::BindOnce(&GrpcCompletionQueueDispatcher::RegisterTag,
                     base::Unretained(&dispatcher_), kTag,
                     tag_available_called_tester_2.GetTagAvailableCallback());
  tag_available_called_tester_1.CallWhenInvoked(
      std::move(reregister_tag_callback));
  tag_available_called_tester_1.CallWhenInvoked(run_loop_1.QuitClosure());

  tag_available_called_tester_2.CallWhenInvoked(run_loop_2.QuitClosure());

  grpc::Alarm alarm_1(&completion_queue_,
                      GprTimespecWithDeltaFromNow(base::Milliseconds(1)), kTag);
  run_loop_1.Run();

  grpc::Alarm alarm_2(&completion_queue_,
                      GprTimespecWithDeltaFromNow(base::Milliseconds(1)), kTag);
  run_loop_2.Run();

  EXPECT_TRUE(tag_available_called_tester_1.has_been_called());
  EXPECT_TRUE(tag_available_called_tester_1.value_of_ok());
  EXPECT_TRUE(tag_available_called_tester_2.has_been_called());
  EXPECT_TRUE(tag_available_called_tester_2.value_of_ok());

  ShutdownDispatcher();
}

}  // namespace brillo
