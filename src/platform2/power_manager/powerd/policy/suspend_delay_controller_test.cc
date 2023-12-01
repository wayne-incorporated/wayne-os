// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/suspend_delay_controller.h"

#include <base/compiler_specific.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/policy/suspend_delay_observer.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/suspend.pb.h"

namespace power_manager::policy {

namespace {

// Maximum amount of time to wait for OnReadyForSuspend() to be called.
constexpr base::TimeDelta kSuspendTimeout = base::Seconds(5);

class TestObserver : public SuspendDelayObserver {
 public:
  TestObserver() = default;
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;

  ~TestObserver() override = default;

  // Must be called before RunUntilReadyForSuspend().
  void set_timeout(base::TimeDelta timeout) { timeout_ = timeout; }

  // Runs |loop_| until OnReadyForSuspend() is called.
  bool RunUntilReadyForSuspend() { return loop_runner_.StartLoop(timeout_); }

  // SuspendDelayObserver implementation:
  void OnReadyForSuspend(SuspendDelayController* controller,
                         int suspend_id) override {
    loop_runner_.StopLoop();
  }

 private:
  // Maximum time to wait for readiness.
  base::TimeDelta timeout_ = kSuspendTimeout;

  TestMainLoopRunner loop_runner_;
};

class SuspendDelayControllerTest : public TestEnvironment {
 public:
  SuspendDelayControllerTest()
      : controller_(
            1, "", SuspendDelayController::kDefaultMaxSuspendDelayTimeout) {
    controller_.AddObserver(&observer_);
  }
  SuspendDelayControllerTest(const SuspendDelayControllerTest&) = delete;
  SuspendDelayControllerTest& operator=(const SuspendDelayControllerTest&) =
      delete;

  ~SuspendDelayControllerTest() override {
    controller_.RemoveObserver(&observer_);
  }

 protected:
  // Calls |controller_|'s RegisterSuspendDelay() method and returns the
  // newly-created delay's ID.
  int RegisterSuspendDelay(base::TimeDelta timeout, const std::string& client) {
    RegisterSuspendDelayRequest request;
    request.set_timeout(timeout.InMicroseconds());
    request.set_description(client + "-desc");
    RegisterSuspendDelayReply reply;
    controller_.RegisterSuspendDelay(request, client, &reply);
    return reply.delay_id();
  }

  // Calls |controller_|'s UnregisterSuspendDelay() method.
  void UnregisterSuspendDelay(int delay_id, const std::string& client) {
    UnregisterSuspendDelayRequest request;
    request.set_delay_id(delay_id);
    controller_.UnregisterSuspendDelay(request, client);
  }

  // Calls |controller_|'s HandleSuspendReadiness() method.
  void HandleSuspendReadiness(int delay_id,
                              int suspend_id,
                              const std::string& client) {
    SuspendReadinessInfo info;
    info.set_delay_id(delay_id);
    info.set_suspend_id(suspend_id);
    controller_.HandleSuspendReadiness(info, client);
  }

  TestObserver observer_;
  SuspendDelayController controller_;
};

}  // namespace

TEST_F(SuspendDelayControllerTest, NoDelays) {
  // The controller should say that it's initially ready to suspend when no
  // delays have been registered.
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // The controller should still say that it's ready to suspend after we request
  // suspending -- there are no delays to wait for.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // The observer should be notified that it's safe to suspend.
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, SingleDelay) {
  // Register a delay.
  const std::string kClient = "client";
  int delay_id = RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // A SuspendImminent signal should be emitted after suspending is requested.
  // The controller shouldn't report readiness now; it's waiting on the delay.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // Tell the controller that the delay is ready and check that the controller
  // reports readiness now.
  HandleSuspendReadiness(delay_id, kSuspendId, kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, CheckMinTimeout) {
  // Request maximum delay.
  const std::string kClient = "client";
  RegisterSuspendDelayRequest request;
  request.set_timeout(-1);
  request.set_description(kClient + "-desc");
  RegisterSuspendDelayReply reply;
  controller_.RegisterSuspendDelay(request, kClient, &reply);

  // A valid delay id should be returned and |min_delay_timeout_ms| should be
  // the maximum suspend delay timeout as a negative timeout was sent in the
  // request.
  EXPECT_GT(reply.delay_id(), 0);
  EXPECT_EQ(
      reply.min_delay_timeout_ms(),
      SuspendDelayController::kDefaultMaxSuspendDelayTimeout.InMilliseconds());
}

TEST_F(SuspendDelayControllerTest, UnregisterDelayBeforeRequestingSuspend) {
  // Register a delay, but unregister it immediately.
  const std::string kClient = "client";
  int delay_id = RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  UnregisterSuspendDelay(delay_id, kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // The controller should immediately report readiness.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, UnregisterDelayAfterRequestingSuspend) {
  // Register a delay.
  const std::string kClient = "client";
  int delay_id = RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // Request suspending.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // If the delay is unregistered while the controller is waiting for it, the
  // controller should start reporting readiness.
  UnregisterSuspendDelay(delay_id, kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, RegisterDelayAfterRequestingSuspend) {
  // Request suspending before any delays have been registered.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // Register a delay now.  The controller should still report readiness.
  const std::string kClient = "client";
  int delay_id = RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // Request suspending again.  The controller should say it isn't ready now.
  const int kNextSuspendId = 6;
  controller_.PrepareForSuspend(kNextSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  HandleSuspendReadiness(delay_id, kNextSuspendId, kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, Timeout) {
  // Register a delay with a short timeout.
  const std::string kClient = "client";
  RegisterSuspendDelay(base::Milliseconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // The controller should report readiness due to the timeout being hit.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, FinishRequest) {
  const std::string kClient = "client";
  RegisterSuspendDelay(base::Milliseconds(1), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // FinishSuspend() calls with bogus IDs should be ignored.
  controller_.FinishSuspend(kSuspendId - 1);
  controller_.FinishSuspend(kSuspendId + 1);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // The controller should report that the system is ready to suspend as soon as
  // the suspend request is cancelled.
  controller_.FinishSuspend(kSuspendId);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // The timer should also be stopped.
  observer_.set_timeout(base::Milliseconds(2));
  EXPECT_FALSE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, DisconnectClientBeforeRequestingSuspend) {
  // Register a delay, but immediately tell the controller that the D-Bus client
  // that registered the delay has disconnected.
  const std::string kClient = "client";
  RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  controller_.HandleDBusClientDisconnected(kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // The delay should have been removed.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, DisconnectClientAfterRequestingSuspend) {
  const std::string kClient = "client";
  RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // If the client is disconnected while the controller is waiting, it should
  // report readiness.
  controller_.HandleDBusClientDisconnected(kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, MultipleSuspendRequests) {
  const std::string kClient = "client";
  int delay_id = RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // Request suspending.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // Before confirming that the delay is ready, request suspending again.
  const int kNextSuspendId = 6;
  controller_.PrepareForSuspend(kNextSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // Report readiness, but do it on behalf of the original suspend attempt.  The
  // controller shouldn't say it's ready yet.
  HandleSuspendReadiness(delay_id, kSuspendId, kClient);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // Now report readiness on behalf of the second suspend attempt.
  HandleSuspendReadiness(delay_id, kNextSuspendId, kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

TEST_F(SuspendDelayControllerTest, MultipleDelays) {
  // Register two delays.
  const std::string kClient1 = "client1";
  int delay_id1 = RegisterSuspendDelay(base::Seconds(8), kClient1);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  const std::string kClient2 = "client2";
  int delay_id2 = RegisterSuspendDelay(base::Seconds(8), kClient2);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // After getting a suspend request, the controller shouldn't report readiness
  // until both delays have confirmed their readiness.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, false);
  EXPECT_FALSE(controller_.ReadyForSuspend());
  HandleSuspendReadiness(delay_id2, kSuspendId, kClient2);
  EXPECT_FALSE(controller_.ReadyForSuspend());
  HandleSuspendReadiness(delay_id1, kSuspendId, kClient1);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

// Controller should wait for |kDarkResumeMinDelay| on dark resume when no
// additional delays are registered.
TEST_F(SuspendDelayControllerTest, DarkResumeNoExternalDelays) {
  // The controller should say that it's initially ready to suspend when no
  // delays have been registered.
  EXPECT_TRUE(controller_.ReadyForSuspend());

  const int kSuspendId = 5;
  const base::TimeDelta kDarkResumeMinDelay = base::Milliseconds(5);
  // The minimum delay controller is expected to wait when in dark resume before
  // saying it is ready for suspend.
  controller_.set_dark_resume_min_delay_for_testing(kDarkResumeMinDelay);

  controller_.PrepareForSuspend(kSuspendId, true);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // The observer should be notified that it's safe to suspend after
  // |kDarkResumeMinDelay| since no other delays are registered.
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

// When a client requests a delay greater than |kDarkResumeMinDelay| controller
// should wait for the client readiness (or its timeout) before saying it is
// ready for suspend.
TEST_F(SuspendDelayControllerTest, DarkResumeSingleDelay) {
  // Register a delay.
  const std::string kClient = "client";
  int delay_id = RegisterSuspendDelay(base::Seconds(8), kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());

  // Set dark resume min delay to 5 milliseconds.
  const base::TimeDelta kDarkResumeMinDelay = base::Milliseconds(5);
  controller_.set_dark_resume_min_delay_for_testing(kDarkResumeMinDelay);

  // The controller shouldn't report readiness now; it's waiting on the both
  // |kDarkResumeMinDelay| and registered client delay.
  const int kSuspendId = 5;
  controller_.PrepareForSuspend(kSuspendId, true);
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // The observers should not be notified after |kDarkResumeMinDelay| as the
  // registered client is not yet ready.
  observer_.set_timeout(kDarkResumeMinDelay);
  EXPECT_FALSE(observer_.RunUntilReadyForSuspend());
  EXPECT_FALSE(controller_.ReadyForSuspend());

  // Tell the controller that registered client is ready and check that the
  // controller reports readiness now.
  HandleSuspendReadiness(delay_id, kSuspendId, kClient);
  EXPECT_TRUE(controller_.ReadyForSuspend());
  EXPECT_TRUE(observer_.RunUntilReadyForSuspend());
  EXPECT_TRUE(controller_.ReadyForSuspend());
}

}  // namespace power_manager::policy
