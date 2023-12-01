// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <tuple>
#include <utility>

#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/routine_observer_for_testing.h"
#include "diagnostics/cros_healthd/routines/volume_button/volume_button.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::WithArg;

constexpr auto kArbitraryButtonType =
    mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeUp;
constexpr auto kArbitraryTimeout = base::Seconds(10);

// Returns the exception info.
std::tuple<uint32_t, std::string> RunRoutineAndWaitForException(
    std::unique_ptr<BaseRoutineControl>& routine) {
  base::test::TestFuture<uint32_t, const std::string&> future;
  routine->SetOnExceptionCallback(future.GetCallback());
  routine->Start();
  return future.Take();
}

mojom::RoutineStatePtr GetRoutineState(
    std::unique_ptr<BaseRoutineControl>& routine) {
  base::test::TestFuture<mojom::RoutineStatePtr> future;
  routine->GetState(future.GetCallback());
  return future.Take();
}

void OnUnexpectedException(uint32_t error, const std::string& reason) {
  CHECK(false) << "An exception has occurred when it shouldn't have.";
}

class VolumeButtonRoutineTest : public testing::Test {
 protected:
  VolumeButtonRoutineTest() = default;
  VolumeButtonRoutineTest(const VolumeButtonRoutineTest&) = delete;
  VolumeButtonRoutineTest& operator=(const VolumeButtonRoutineTest&) = delete;

  void CreateRoutine(mojom::VolumeButtonRoutineArgument::ButtonType type,
                     base::TimeDelta timeout) {
    auto arg = mojom::VolumeButtonRoutineArgument::New();
    arg->type = type;
    arg->timeout = timeout;
    routine =
        std::make_unique<VolumeButtonRoutine>(&mock_context_, std::move(arg));
  }

  void ExpectBindEventObserver() {
    EXPECT_CALL(*mock_executor(), MonitorVolumeButton)
        .WillOnce(WithArg<0>([=](auto volume_button_observer) {
          volume_button_observer_.Bind(std::move(volume_button_observer));
        }));
  }

  // Returns a RoutineObserverForTesting to monitor the routine state. Caller
  // must hold the returned object. Otherwise, the |on_finished| callback won't
  // work.
  [[nodiscard]] std::unique_ptr<RoutineObserverForTesting>
  StartRoutineAndObserve(base::OnceClosure on_finished) {
    routine->SetOnExceptionCallback(base::BindOnce(&OnUnexpectedException));
    auto observer =
        std::make_unique<RoutineObserverForTesting>(std::move(on_finished));
    routine->AddObserver(observer->receiver_.BindNewPipeAndPassRemote());
    routine->Start();
    return observer;
  }

  void EmitVolumeButtonEvent(mojom::VolumeButtonObserver::Button button) {
    // Emit an arbitrary state.
    volume_button_observer_->OnEvent(
        button, mojom::VolumeButtonObserver::ButtonState::kUp);
  }

  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  mojo::Remote<mojom::VolumeButtonObserver> volume_button_observer_;
  MockContext mock_context_;
  std::unique_ptr<BaseRoutineControl> routine;
};

TEST_F(VolumeButtonRoutineTest, InitializedStateBeforeStart) {
  CreateRoutine(kArbitraryButtonType, kArbitraryTimeout);
  auto result = GetRoutineState(routine);
  EXPECT_EQ(result->percentage, 0);
  EXPECT_TRUE(result->state_union->is_initialized());
}

TEST_F(VolumeButtonRoutineTest, ErrorForUnknownButtonType) {
  CreateRoutine(
      mojom::VolumeButtonRoutineArgument::ButtonType::kUnmappedEnumField,
      kArbitraryTimeout);
  auto [error_unused, reason] = RunRoutineAndWaitForException(routine);
  EXPECT_EQ(reason, "Unknown volume button type.");
}

TEST_F(VolumeButtonRoutineTest, ErrorWhenTimeoutTooShort) {
  CreateRoutine(kArbitraryButtonType, base::Seconds(0));
  auto [error_unused, reason] = RunRoutineAndWaitForException(routine);
  EXPECT_EQ(reason, "Timeout must be positive.");
}

TEST_F(VolumeButtonRoutineTest, ErrorWhenTimeoutTooLong) {
  CreateRoutine(kArbitraryButtonType, base::Seconds(601));
  auto [error_unused, reason] = RunRoutineAndWaitForException(routine);
  EXPECT_EQ(reason, "Timeout cannot be longer than 600 seconds.");
}

TEST_F(VolumeButtonRoutineTest, PassedWhenEventReceived) {
  ExpectBindEventObserver();

  CreateRoutine(mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeUp,
                kArbitraryTimeout);

  base::RunLoop run_loop;
  auto observer = StartRoutineAndObserve(run_loop.QuitClosure());

  EmitVolumeButtonEvent(mojom::VolumeButtonObserver::Button::kVolumeUp);

  run_loop.Run();

  const auto& result = observer->state_;
  EXPECT_EQ(result->percentage, 100);
  ASSERT_TRUE(result->state_union->is_finished());
  EXPECT_TRUE(result->state_union->get_finished()->has_passed);
}

TEST_F(VolumeButtonRoutineTest, FailedWhenTimeout) {
  ExpectBindEventObserver();

  const base::TimeDelta timeout = base::Seconds(10);
  CreateRoutine(kArbitraryButtonType, timeout);

  base::RunLoop run_loop;
  auto observer = StartRoutineAndObserve(run_loop.QuitClosure());

  task_environment_.FastForwardBy(timeout);

  run_loop.Run();

  const auto& result = observer->state_;
  EXPECT_EQ(result->percentage, 100);
  ASSERT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
}

TEST_F(VolumeButtonRoutineTest, FailedWhenTimeoutIfNoCorrectButtonPressed) {
  ExpectBindEventObserver();

  const base::TimeDelta timeout = base::Seconds(10);
  CreateRoutine(mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeUp,
                timeout);

  base::RunLoop run_loop;
  auto observer = StartRoutineAndObserve(run_loop.QuitClosure());

  EmitVolumeButtonEvent(mojom::VolumeButtonObserver::Button::kVolumeDown);

  task_environment_.FastForwardBy(timeout);

  run_loop.Run();

  const auto& result = observer->state_;
  EXPECT_EQ(result->percentage, 100);
  ASSERT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
}

TEST_F(VolumeButtonRoutineTest, NoCrashAfterRoutineFinished) {
  ExpectBindEventObserver();

  const base::TimeDelta timeout = base::Seconds(10);
  CreateRoutine(mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeUp,
                timeout);

  base::RunLoop run_loop;
  auto observer = StartRoutineAndObserve(run_loop.QuitClosure());

  EmitVolumeButtonEvent(mojom::VolumeButtonObserver::Button::kVolumeUp);

  run_loop.Run();

  const auto& result = observer->state_;
  EXPECT_TRUE(result->state_union->is_finished());

  task_environment_.FastForwardBy(timeout);
  // Expect no crash.
}

TEST_F(VolumeButtonRoutineTest, ErrorWhenEventSubscriptionFailed) {
  ExpectBindEventObserver();

  CreateRoutine(kArbitraryButtonType, kArbitraryTimeout);

  base::test::TestFuture<uint32_t, const std::string&> future;
  routine->SetOnExceptionCallback(future.GetCallback());
  routine->Start();

  volume_button_observer_.reset();

  auto [error_unused, reason] = future.Take();
  EXPECT_EQ(reason, "Unable to listen for volume button events.");
}

}  // namespace
}  // namespace diagnostics
