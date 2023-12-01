// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/json/json_writer.h>
#include <base/test/task_environment.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/cros_healthd/routine_adapter.h"
#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

mojom::RoutineDetailPtr CreateEmptyMemoryDetail() {
  auto detail = mojom::MemoryRoutineDetail::New();
  detail->bytes_tested = 0;
  detail->result = mojom::MemtesterResult::New();
  return mojom::RoutineDetail::NewMemory(std::move(detail));
}

}  // namespace

namespace diagnostics {

class RoutineControlImplPeer final : public BaseRoutineControl {
 public:
  explicit RoutineControlImplPeer(
      base::OnceCallback<void(uint32_t error, const std::string& reason)>
          on_exception_)
      : BaseRoutineControl() {
    SetOnExceptionCallback(std::move(on_exception_));
  }
  RoutineControlImplPeer(const RoutineControlImplPeer&) = delete;
  RoutineControlImplPeer& operator=(const RoutineControlImplPeer&) = delete;
  ~RoutineControlImplPeer() override = default;

  int GetObserverSize() { return observers_.size(); }

  void OnStart() override { return; }

  void SetRunningImpl() {
    SetRunningState();
    // Flush observes_ to make sure all commands on observer side has been
    // executed.
    observers_.FlushForTesting();
  }

  void SetWaitingImpl(mojom::RoutineStateWaiting::Reason reason,
                      const std::string& message) {
    SetWaitingState(reason, message);
    // Flush observes_ to make sure all commands on observer side has been
    // executed.
    observers_.FlushForTesting();
  }

  void SetFinishedImpl(bool passed, mojom::RoutineDetailPtr state) {
    SetFinishedState(passed, std::move(state));
    // Flush observes_ to make sure all commands on observer side has been
    // executed.
    observers_.FlushForTesting();
  }

  void SetPercentageImpl(uint8_t percentage) {
    SetPercentage(percentage);
    // Flush observes_ to make sure all commands on observer side has been
    // executed.
    observers_.FlushForTesting();
  }

  void RaiseException(const std::string& reason) {
    BaseRoutineControl::RaiseException(reason);
  }

  mojo::Receiver<ash::cros_healthd::mojom::RoutineControl>* receiver() {
    return &receiver_;
  }

 private:
  mojo::Receiver<ash::cros_healthd::mojom::RoutineControl> receiver_{this};
};

namespace {

using ::testing::_;
using ::testing::AtLeast;
using ::testing::StrictMock;

class MockObserver : public mojom::RoutineObserver {
 public:
  explicit MockObserver(
      mojo::PendingReceiver<ash::cros_healthd::mojom::RoutineObserver> receiver)
      : receiver_{this /* impl */, std::move(receiver)} {}
  MOCK_METHOD(void,
              OnRoutineStateChange,
              (ash::cros_healthd::mojom::RoutineStatePtr),
              (override));

 private:
  const mojo::Receiver<ash::cros_healthd::mojom::RoutineObserver> receiver_;
};

class BaseRoutineControlTest : public testing::Test {
 public:
  BaseRoutineControlTest() {
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  }

 protected:
  base::OnceCallback<void(uint32_t, const std::string&)> ExpectNoException() {
    return base::BindOnce([](uint32_t error, const std::string& reason) {
      EXPECT_TRUE(false) << "No Exception should occur: " << reason;
    });
  }

  base::test::SingleThreadTaskEnvironment task_environment_;
};

class RoutineAdapterTest : public testing::Test {
 protected:
  RoutineAdapterTest() = default;
  RoutineAdapterTest(const RoutineAdapterTest&) = delete;
  RoutineAdapterTest& operator=(const RoutineAdapterTest&) = delete;

  void SetUp() override {
    routine_control_ = std::make_unique<RoutineControlImplPeer>(base::BindOnce(
        &RoutineAdapterTest::OnRoutineException, base::Unretained(this)));
    // Use Memory Routine argument here to prevent causing error. Routine
    // Adapter will bind to routine_control regardless of the Routine Argument
    // type.
    routine_adapter_ =
        std::make_unique<RoutineAdapter>(mojom::RoutineArgument::Tag::kMemory);

    routine_control_->receiver()->Bind(
        routine_adapter_->BindNewPipeAndPassReceiver());
  }

  void SetUpWithUnrecognizedRoutineArgument() {
    routine_control_ = std::make_unique<RoutineControlImplPeer>(base::BindOnce(
        &RoutineAdapterTest::OnRoutineException, base::Unretained(this)));
    routine_adapter_ = std::make_unique<RoutineAdapter>(
        mojom::RoutineArgument::Tag::kUnrecognizedArgument);
    routine_control_->receiver()->Bind(
        routine_adapter_->BindNewPipeAndPassReceiver());
  }

  void OnRoutineException(uint32_t error, const std::string& reason) {
    routine_control_->receiver()->ResetWithReason(error, reason);
  }

  mojom::RoutineUpdatePtr GetUpdate() {
    mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
    routine_adapter_->PopulateStatusUpdate(update.get(), true);
    return update;
  }

  std::unique_ptr<RoutineControlImplPeer> routine_control_;
  std::unique_ptr<RoutineAdapter> routine_adapter_;

 private:
  base::test::TaskEnvironment task_environment_;
};

void ExpectOutput(int8_t expect_percentage,
                  mojom::RoutineStateUnionPtr expect_state,
                  mojom::RoutineStatePtr got_state) {
  EXPECT_EQ(got_state->percentage, expect_percentage);
  EXPECT_EQ(got_state->state_union, expect_state);
  return;
}

// Test that we can successfully call getState.
TEST_F(BaseRoutineControlTest, GetState) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.GetState(base::BindOnce(&ExpectOutput, 0,
                             mojom::RoutineStateUnion::NewInitialized(
                                 mojom::RoutineStateInitialized::New())));
}

// Test that state can successfully set percentage.
TEST_F(BaseRoutineControlTest, SetPercentage) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetPercentageImpl(50);
  rc.GetState(base::BindOnce(
      &ExpectOutput, 50,
      mojom::RoutineStateUnion::NewRunning(mojom::RoutineStateRunning::New())));
}

// Test that state will return exception for setting percentage over 100.
TEST_F(BaseRoutineControlTest, SetOver100Percentage) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  EXPECT_DEATH_IF_SUPPORTED(rc.SetPercentageImpl(101), "");
}

// Test that state will return exception for setting percentage that decreased.
TEST_F(BaseRoutineControlTest, SetDecreasingPercentage) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetPercentageImpl(50);
  EXPECT_DEATH_IF_SUPPORTED(rc.SetPercentageImpl(40), "");
}

// Test that state will return exception for setting percentage that decreased.
TEST_F(BaseRoutineControlTest, SetPercentageWithoutStart) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  EXPECT_DEATH_IF_SUPPORTED(rc.SetPercentageImpl(50), "");
}

// Test that state can successfully enter running state from start.
TEST_F(BaseRoutineControlTest, EnterRunningState) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.GetState(base::BindOnce(
      &ExpectOutput, 0,
      mojom::RoutineStateUnion::NewRunning(mojom::RoutineStateRunning::New())));
}

// Test that state can enter running from waiting.
TEST_F(BaseRoutineControlTest, EnterRunningStateFromWaiting) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                        kWaitingToBeScheduled,
                    "");
  rc.SetRunningImpl();
  rc.GetState(base::BindOnce(
      &ExpectOutput, 0,
      mojom::RoutineStateUnion::NewRunning(mojom::RoutineStateRunning::New())));
}

// Test that state cannot enter running from initialized.
TEST_F(BaseRoutineControlTest, CannotEnterRunningStateWithoutStarting) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  EXPECT_DEATH(rc.SetRunningImpl(), "state");
}

// Test that state cannot enter running from finished.
TEST_F(BaseRoutineControlTest, CannotEnterRunningStateFromFinished) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetFinishedImpl(true, nullptr);
  EXPECT_DEATH_IF_SUPPORTED(rc.SetRunningImpl(), "");
}

// Test that state can enter running from running.
TEST_F(BaseRoutineControlTest, EnterRunningStateFromRunning) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetRunningImpl();
  rc.SetRunningImpl();
  rc.GetState(base::BindOnce(
      &ExpectOutput, 0,
      mojom::RoutineStateUnion::NewRunning(mojom::RoutineStateRunning::New())));
}

// Test that state can successfully enter waiting from running.
TEST_F(BaseRoutineControlTest, EnterWaitingStateFromRunning) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();

  rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                        kWaitingToBeScheduled,
                    "");
  rc.GetState(base::BindOnce(
      &ExpectOutput, 0,
      mojom::RoutineStateUnion::NewWaiting(mojom::RoutineStateWaiting::New(
          mojom::RoutineStateWaiting::Reason::kWaitingToBeScheduled, ""))));
}

// Test that state cannot enter waiting from initialized.
TEST_F(BaseRoutineControlTest, CannotEnterWaitingStateFromInitialized) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  EXPECT_DEATH_IF_SUPPORTED(
      rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                            kWaitingToBeScheduled,
                        ""),
      "");
}

// Test that state cannot enter waiting from finished.
TEST_F(BaseRoutineControlTest, CannotEnterWaitingStateFromFinished) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetFinishedImpl(true, nullptr);
  EXPECT_DEATH_IF_SUPPORTED(
      rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                            kWaitingToBeScheduled,
                        ""),
      "");
}

// Test that state cannot enter waiting from waiting.
TEST_F(BaseRoutineControlTest, CannotEnterWaitingStateFromWaiting) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();

  rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                        kWaitingToBeScheduled,
                    "");
  EXPECT_DEATH_IF_SUPPORTED(
      rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                            kWaitingToBeScheduled,
                        ""),
      "");
}

// Test that state can successfully enter finished from running.
TEST_F(BaseRoutineControlTest, EnterFinishedStateFromRunning) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetRunningImpl();
  rc.SetFinishedImpl(true, nullptr);
  rc.GetState(
      base::BindOnce(&ExpectOutput, 100,
                     mojom::RoutineStateUnion::NewFinished(
                         mojom::RoutineStateFinished::New(true, nullptr))));
}

// Test that state cannot enter finished from initialized.
TEST_F(BaseRoutineControlTest, CannotEnterFinishedStateFromInitialized) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  EXPECT_DEATH_IF_SUPPORTED(rc.SetFinishedImpl(true, nullptr), "");
}

// Test that state cannot enter finished from waiting.
TEST_F(BaseRoutineControlTest, CannotEnterFinishedStateFromWaiting) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();

  rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                        kWaitingToBeScheduled,
                    "");
  EXPECT_DEATH_IF_SUPPORTED(rc.SetFinishedImpl(true, nullptr), "");
}

// Test that state cannot enter finished from finished.
TEST_F(BaseRoutineControlTest, CannotEnterFinishedStateFromFinished) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  rc.Start();
  rc.SetFinishedImpl(true, nullptr);
  EXPECT_DEATH_IF_SUPPORTED(rc.SetFinishedImpl(true, nullptr), "");
}

// Test that we can successfully notify one observer.
TEST_F(BaseRoutineControlTest, NotifyOneObserver) {
  auto rc = RoutineControlImplPeer(ExpectNoException());
  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_1;
  auto observer_1 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_1.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_1));
  EXPECT_CALL(*observer_1.get(), OnRoutineStateChange(_))
      .Times(AtLeast(1))
      .WillOnce(testing::WithArg<0>(
          testing::Invoke([=](ash::cros_healthd::mojom::RoutineStatePtr state) {
            EXPECT_TRUE(state->state_union->is_running());
          })))
      .WillOnce(testing::WithArg<0>(
          testing::Invoke([=](ash::cros_healthd::mojom::RoutineStatePtr state) {
            EXPECT_TRUE(state->state_union->is_waiting());
          })))
      .WillOnce(testing::WithArg<0>(
          testing::Invoke([=](ash::cros_healthd::mojom::RoutineStatePtr state) {
            EXPECT_TRUE(state->state_union->is_running());
          })))
      .WillOnce(testing::WithArg<0>(
          testing::Invoke([=](ash::cros_healthd::mojom::RoutineStatePtr state) {
            EXPECT_TRUE(state->state_union->is_finished());
          })));
  rc.Start();
  rc.SetWaitingImpl(ash::cros_healthd::mojom::RoutineStateWaiting::Reason::
                        kWaitingToBeScheduled,
                    "");
  rc.SetRunningImpl();
  rc.SetFinishedImpl(true, nullptr);
}

// Test that we can successfully notify multiple observers.
TEST_F(BaseRoutineControlTest, NotifyMultipleObservers) {
  auto rc = RoutineControlImplPeer(ExpectNoException());

  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_1;
  auto observer_1 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_1.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_1));

  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_2;
  auto observer_2 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_2.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_2));

  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_3;
  auto observer_3 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_3.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_3));
  EXPECT_CALL(*observer_1.get(), OnRoutineStateChange(_)).Times(AtLeast(1));
  EXPECT_CALL(*observer_2.get(), OnRoutineStateChange(_)).Times(AtLeast(1));
  EXPECT_CALL(*observer_3.get(), OnRoutineStateChange(_)).Times(AtLeast(1));

  rc.Start();
  rc.SetFinishedImpl(true, nullptr);
}

// Test that we can successfully notify other observers after an observer has
// disconnected.
TEST_F(BaseRoutineControlTest, DisconnectedObserver) {
  auto rc = RoutineControlImplPeer(ExpectNoException());

  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_1;
  auto observer_1 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_1.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_1));

  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_2;
  auto observer_2 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_2.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_2));

  mojo::PendingRemote<mojom::RoutineObserver> observer_remote_3;
  auto observer_3 = std::make_unique<StrictMock<MockObserver>>(
      observer_remote_3.InitWithNewPipeAndPassReceiver());
  rc.AddObserver(std::move(observer_remote_3));

  EXPECT_CALL(*observer_1.get(), OnRoutineStateChange(_)).Times(AtLeast(1));
  EXPECT_CALL(*observer_2.get(), OnRoutineStateChange(_)).Times(AtLeast(1));
  EXPECT_CALL(*observer_3.get(), OnRoutineStateChange(_)).Times(0);

  // observer disconnected, Remote set should now only notify two observers.
  observer_3.reset();
  rc.Start();
  rc.SetFinishedImpl(true, nullptr);
}

TEST_F(RoutineAdapterTest, RoutinePassed) {
  routine_adapter_->Start();
  routine_adapter_->FlushRoutineControlForTesting();

  // Check if started.
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // Check if finished and passed.
  routine_control_->SetFinishedImpl(true, CreateEmptyMemoryDetail());
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(RoutineAdapterTest, RoutineFailed) {
  routine_adapter_->Start();
  routine_adapter_->FlushRoutineControlForTesting();

  // Check if started.
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // Check if finished and failed.
  routine_control_->SetFinishedImpl(false, CreateEmptyMemoryDetail());
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(RoutineAdapterTest, SetRoutineStatus) {
  // Check for initial state.
  routine_adapter_->Start();
  routine_adapter_->FlushRoutineControlForTesting();
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kRunning);
  EXPECT_EQ(routine_adapter_->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // Check for waiting state.
  routine_control_->SetWaitingImpl(
      mojom::RoutineStateWaiting::Reason::kWaitingToBeScheduled,
      "Waiting Reason");
  routine_adapter_->FlushRoutineControlForTesting();
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kRunning);
  EXPECT_EQ(routine_adapter_->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // Check for finished state.
  routine_control_->SetRunningImpl();
  routine_control_->SetFinishedImpl(true, CreateEmptyMemoryDetail());
  routine_adapter_->FlushRoutineControlForTesting();
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kPassed);
  EXPECT_EQ(routine_adapter_->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(RoutineAdapterTest, SetRoutinePercentage) {
  // Check for initial state.
  routine_adapter_->Start();
  routine_adapter_->FlushRoutineControlForTesting();
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 0);

  // Check for setting different percentage.
  routine_control_->SetPercentageImpl(50);
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 50);

  // Check for finished state.
  routine_control_->SetFinishedImpl(true, CreateEmptyMemoryDetail());
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 100);
}

TEST_F(RoutineAdapterTest, RoutineError) {
  routine_adapter_->Start();
  routine_adapter_->FlushRoutineControlForTesting();

  routine_control_->RaiseException("Error Reason");
  routine_adapter_->FlushRoutineControlForTesting();
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kError);
  EXPECT_EQ(
      update->routine_update_union->get_noninteractive_update()->status_message,
      "Error Reason");
}

TEST_F(RoutineAdapterTest, RoutineCancel) {
  routine_adapter_->Start();
  routine_adapter_->FlushRoutineControlForTesting();

  routine_adapter_->Cancel();
  // No need to flush remote since the mojo connection has been reset.
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kCancelled);
}

// There should not be a case where routine is initialized without running in
// the V1 Routine API. However, still test to make sure in the worst case the
// program still won't crash.
TEST_F(RoutineAdapterTest, PopulateStatusUpdateBeforeInitialized) {
  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 0);
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kRunning);
}

TEST_F(RoutineAdapterTest, UnrecognizedRoutineArgument) {
  SetUpWithUnrecognizedRoutineArgument();

  mojom::RoutineUpdatePtr update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kUnknown);
}

}  // namespace
}  // namespace diagnostics
