// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/subproc_routine.h"

#include <cstdint>
#include <list>
#include <optional>
#include <utility>
#include <vector>

#include <base/command_line.h>
#include <base/test/simple_test_tick_clock.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/diag_process_adapter.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::AtMost;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::Test;

constexpr base::TimeDelta kPredictedDuration = base::Seconds(10);

void CheckRoutineUpdate(uint32_t progress_percent,
                        std::string status_message,
                        mojom::DiagnosticRoutineStatusEnum status,
                        const mojom::RoutineUpdate& update) {
  EXPECT_EQ(update.progress_percent, progress_percent);
  VerifyNonInteractiveUpdate(update.routine_update_union, status,
                             status_message);
}

class MockCallback {
 public:
  MOCK_METHOD(bool, PreStart, ());
  MOCK_METHOD(void, PostStop, ());
};

class MockDiagProcessAdapter : public DiagProcessAdapter {
 public:
  MOCK_METHOD(base::TerminationStatus,
              GetStatus,
              (const base::ProcessHandle&),
              (const, override));
  MOCK_METHOD(bool,
              StartProcess,
              (const std::vector<std::string>&, base::ProcessHandle*),
              (override));
  MOCK_METHOD(bool, KillProcess, (const base::ProcessHandle&), (override));
};

class SubprocRoutineTest : public Test {
 protected:
  SubprocRoutineTest() = default;
  SubprocRoutineTest(const SubprocRoutineTest&) = delete;
  SubprocRoutineTest& operator=(const SubprocRoutineTest&) = delete;

  SubprocRoutine* routine() { return routine_.get(); }

  mojom::RoutineUpdate* update() { return &update_; }

  StrictMock<MockDiagProcessAdapter>* mock_adapter() { return mock_adapter_; }
  base::SimpleTestTickClock* tick_clock() { return tick_clock_; }

  std::optional<mojom::DiagnosticRoutineStatusEnum>
  last_received_status_change() {
    return last_received_status_change_;
  }

  void CreateRoutine(base::TimeDelta predicted_duration = kPredictedDuration) {
    auto mock_adapter_ptr =
        std::make_unique<StrictMock<MockDiagProcessAdapter>>();
    mock_adapter_ = mock_adapter_ptr.get();
    auto tick_clock_ptr = std::make_unique<base::SimpleTestTickClock>();
    tick_clock_ = tick_clock_ptr.get();

    // We never actually run subprocesses in this unit test, because this module
    // is not actually responsible for process invocation, and we trust the
    // DiagProcessAdapter to do things appropriately.
    auto command_line = base::CommandLine({"/dev/null"});

    routine_ = std::make_unique<SubprocRoutine>(
        std::move(mock_adapter_ptr), std::move(tick_clock_ptr),
        std::list<base::CommandLine>{command_line}, predicted_duration);
    routine_->RegisterStatusChangedCallback(base::BindRepeating(
        &SubprocRoutineTest::OnRoutineStatusChanged, base::Unretained(this)));
  }

  void CreateRoutineWithMultipleCmds(
      base::TimeDelta predicted_duration = kPredictedDuration) {
    auto mock_adapter_ptr =
        std::make_unique<StrictMock<MockDiagProcessAdapter>>();
    mock_adapter_ = mock_adapter_ptr.get();
    auto tick_clock_ptr = std::make_unique<base::SimpleTestTickClock>();
    tick_clock_ = tick_clock_ptr.get();

    // We never actually run subprocesses in this unit test, because this module
    // is not actually responsible for process invocation, and we trust the
    // DiagProcessAdapter to do things appropriately.
    auto command_line = base::CommandLine({"/dev/null"});
    auto command_line1 = base::CommandLine({"/dev/zero"});

    routine_ = std::make_unique<SubprocRoutine>(
        std::move(mock_adapter_ptr), std::move(tick_clock_ptr),
        std::list<base::CommandLine>{command_line, command_line1},
        predicted_duration);
    routine_->RegisterStatusChangedCallback(base::BindRepeating(
        &SubprocRoutineTest::OnRoutineStatusChanged, base::Unretained(this)));
  }

  void RegisterPreStartCallback(base::OnceCallback<bool()> callback) {
    routine_->RegisterPreStartCallback(std::move(callback));
  }

  void RegisterPostStopCallback(base::OnceClosure callback) {
    routine_->RegisterPostStopCallback(std::move(callback));
  }

  void RunRoutineWithTerminationStatus(base::TerminationStatus status) {
    EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                        Return(true)));
    routine_->Start();
    PopulateStatusUpdateForRunningRoutine(status);
  }

  void PopulateStatusUpdateForRunningRoutine(base::TerminationStatus status) {
    EXPECT_CALL(*mock_adapter_, GetStatus(_)).WillOnce(Return(status));
    routine_->PopulateStatusUpdate(&update_, true);
  }

  void DestroyRoutine() { routine_.reset(); }

  void OnRoutineStatusChanged(mojom::DiagnosticRoutineStatusEnum status) {
    last_received_status_change_ = status;
  }

 private:
  StrictMock<MockDiagProcessAdapter>* mock_adapter_;  // Owned by |routine_|.
  base::SimpleTestTickClock* tick_clock_;             // Owned by |routine_|.
  std::unique_ptr<SubprocRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
  std::optional<mojom::DiagnosticRoutineStatusEnum>
      last_received_status_change_;
};

TEST_F(SubprocRoutineTest, InvokeSubprocWithSuccess) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));

  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .WillOnce(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));
  routine()->Start();
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);

  CheckRoutineUpdate(100, kSubprocRoutineSucceededMessage,
                     mojom::DiagnosticRoutineStatusEnum::kPassed, update);
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithMultipleCmdsWithSuccess) {
  CreateRoutineWithMultipleCmds();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .Times(2)
      .WillRepeatedly(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                            Return(true)));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .Times(2)
      .WillRepeatedly(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));

  routine()->Start();

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  tick_clock()->Advance(base::Seconds(5));
  routine()->PopulateStatusUpdate(&update, false);
  CheckRoutineUpdate(50, kSubprocRoutineProcessRunningMessage,
                     mojom::DiagnosticRoutineStatusEnum::kRunning, update);
  routine()->PopulateStatusUpdate(&update, false);
  CheckRoutineUpdate(100, kSubprocRoutineSucceededMessage,
                     mojom::DiagnosticRoutineStatusEnum::kPassed, update);
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithPreStartCallbackSuccess) {
  CreateRoutine();
  StrictMock<MockCallback>* mock_callback = new StrictMock<MockCallback>();
  EXPECT_CALL(*mock_callback, PreStart()).WillOnce(Return(true));
  RegisterPreStartCallback(
      base::BindOnce(&MockCallback::PreStart, base::Owned(mock_callback)));
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .WillOnce(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));

  routine()->Start();

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);
  CheckRoutineUpdate(100, kSubprocRoutineSucceededMessage,
                     mojom::DiagnosticRoutineStatusEnum::kPassed, update);
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithPreStartCallbackFailure) {
  CreateRoutine();
  StrictMock<MockCallback>* mock_callback = new StrictMock<MockCallback>();
  EXPECT_CALL(*mock_callback, PreStart()).WillOnce(Return(false));
  base::OnceCallback<bool()> cb =
      base::BindOnce(&MockCallback::PreStart, base::Owned(mock_callback));
  RegisterPreStartCallback(std::move(cb));

  routine()->Start();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kFailedToStart);
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kFailedToStart);
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithPostStopCallback) {
  CreateRoutine();
  StrictMock<MockCallback>* mock_callback = new StrictMock<MockCallback>();
  EXPECT_CALL(*mock_callback, PostStop());
  RegisterPostStopCallback(
      base::BindOnce(&MockCallback::PostStop, base::Owned(mock_callback)));
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .WillOnce(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));

  routine()->Start();

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);
  CheckRoutineUpdate(100, kSubprocRoutineSucceededMessage,
                     mojom::DiagnosticRoutineStatusEnum::kPassed, update);
  DestroyRoutine();
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithPostStopCallbackWithoutStart) {
  CreateRoutine();
  StrictMock<MockCallback>* mock_callback = new StrictMock<MockCallback>();
  EXPECT_CALL(*mock_callback, PostStop());
  RegisterPostStopCallback(
      base::BindOnce(&MockCallback::PostStop, base::Owned(mock_callback)));
  EXPECT_EQ(last_received_status_change(), std::nullopt);
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithMultipleCmdsAndPreStartCallback) {
  CreateRoutineWithMultipleCmds();
  StrictMock<MockCallback>* mock_callback = new StrictMock<MockCallback>();
  EXPECT_CALL(*mock_callback, PreStart()).WillOnce(Return(true));
  RegisterPreStartCallback(
      base::BindOnce(&MockCallback::PreStart, base::Owned(mock_callback)));
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .Times(2)
      .WillRepeatedly(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                            Return(true)));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .Times(2)
      .WillRepeatedly(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));

  routine()->Start();

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  tick_clock()->Advance(base::Seconds(5));
  routine()->PopulateStatusUpdate(&update, false);
  CheckRoutineUpdate(50, kSubprocRoutineProcessRunningMessage,
                     mojom::DiagnosticRoutineStatusEnum::kRunning, update);
  routine()->PopulateStatusUpdate(&update, false);
  CheckRoutineUpdate(100, kSubprocRoutineSucceededMessage,
                     mojom::DiagnosticRoutineStatusEnum::kPassed, update);
}

TEST_F(SubprocRoutineTest, InvokeSubprocWithFailure) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .WillOnce(Return(base::TERMINATION_STATUS_ABNORMAL_TERMINATION));
  routine()->Start();

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);

  CheckRoutineUpdate(100, kSubprocRoutineFailedMessage,
                     mojom::DiagnosticRoutineStatusEnum::kFailed, update);
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(SubprocRoutineTest, FailInvokingSubproc) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _)).WillOnce(Return(false));
  routine()->Start();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kFailedToStart);
}

TEST_F(SubprocRoutineTest, TestHalfProgressPercent) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .Times(AtMost(2))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));

  routine()->Start();

  tick_clock()->Advance(base::Seconds(5));

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);

  CheckRoutineUpdate(50, kSubprocRoutineProcessRunningMessage,
                     mojom::DiagnosticRoutineStatusEnum::kRunning, update);
}

TEST_F(SubprocRoutineTest, TestHalfProgressThenCancel) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));
  EXPECT_CALL(*mock_adapter(), KillProcess(_)).Times(AtMost(1));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .Times(AtMost(4))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_ABNORMAL_TERMINATION));

  routine()->Start();

  tick_clock()->Advance(base::Seconds(5));
  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);

  CheckRoutineUpdate(50, kSubprocRoutineProcessRunningMessage,
                     mojom::DiagnosticRoutineStatusEnum::kRunning, update);

  routine()->Cancel();

  tick_clock()->Advance(base::Seconds(1));

  routine()->PopulateStatusUpdate(&update, false);

  CheckRoutineUpdate(50, kSubprocRoutineProcessCancellingMessage,
                     mojom::DiagnosticRoutineStatusEnum::kCancelling, update);
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kCancelling);

  // Now the process should appear dead
  routine()->PopulateStatusUpdate(&update, false);

  CheckRoutineUpdate(50, kSubprocRoutineCancelledMessage,
                     mojom::DiagnosticRoutineStatusEnum::kCancelled, update);
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kCancelled);
}

// Test that we can handle repeated cancel commands to a process that is slow to
// die.
TEST_F(SubprocRoutineTest, RepeatedCancelCommands) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));
  EXPECT_CALL(*mock_adapter(), KillProcess(_));
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .Times(4)
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING))
      .WillOnce(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));

  routine()->Start();
  routine()->Cancel();

  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  routine()->PopulateStatusUpdate(&update, false);

  VerifyNonInteractiveUpdate(update.routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kCancelling,
                             kSubprocRoutineProcessCancellingMessage);

  routine()->Cancel();

  routine()->PopulateStatusUpdate(&update, false);

  VerifyNonInteractiveUpdate(update.routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kCancelled,
                             kSubprocRoutineCancelledMessage);
}

// Test that SubprocRoutine handles an invalid termination status returned from
// the diag process adapter.
TEST_F(SubprocRoutineTest, InvalidTerminationStatus) {
  CreateRoutine();
  RunRoutineWithTerminationStatus(static_cast<base::TerminationStatus>(-1));
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kSubprocRoutineErrorMessage);
  EXPECT_EQ(last_received_status_change(),
            mojom::DiagnosticRoutineStatusEnum::kError);
}

// Test that SubprocRoutine handles a command line that fails to start.
TEST_F(SubprocRoutineTest, FailedToStart) {
  CreateRoutine();
  RunRoutineWithTerminationStatus(base::TERMINATION_STATUS_LAUNCH_FAILED);
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailedToStart,
                             kSubprocRoutineFailedToLaunchProcessMessage);
}

// Test that we attempt to kill a running process during destruction.
TEST_F(SubprocRoutineTest, KillProcessDuringDestruction) {
  CreateRoutine();
  EXPECT_CALL(*mock_adapter(), StartProcess(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(base::GetCurrentProcessHandle()),
                      Return(true)));

  routine()->Start();

  // When we kill the routine, it should attempt to kill a running process.
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .WillOnce(Return(base::TERMINATION_STATUS_STILL_RUNNING));
  EXPECT_CALL(*mock_adapter(), KillProcess(_));

  DestroyRoutine();
}

// Test that we report the correct progress percent when we don't know the
// routine's predicted duration.
TEST_F(SubprocRoutineTest, NoPredictedDuration) {
  CreateRoutine(/*predicted_duration=*/base::TimeDelta());
  RunRoutineWithTerminationStatus(base::TERMINATION_STATUS_STILL_RUNNING);
  EXPECT_EQ(update()->progress_percent,
            kSubprocRoutineFakeProgressPercentUnknown);

  // Since we left a zombie process, expect the destructor to try and kill it.
  EXPECT_CALL(*mock_adapter(), GetStatus(_))
      .WillOnce(Return(base::TERMINATION_STATUS_NORMAL_TERMINATION));
}

// Test that calling resume doesn't crash.
TEST_F(SubprocRoutineTest, Resume) {
  CreateRoutine();
  routine()->Resume();
}

// Test that we can create a SubprocRoutine with the production constructor.
TEST(SubprocRoutineTestNoFixture, ProductionConstructor) {
  std::unique_ptr<SubprocRoutine> prod_routine =
      std::make_unique<SubprocRoutine>(
          base::CommandLine({"/dev/null"}),
          /*predicted_duration=*/base::TimeDelta());
  mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                              mojom::RoutineUpdateUnionPtr()};
  prod_routine->PopulateStatusUpdate(&update, false);
  VerifyNonInteractiveUpdate(update.routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kReady,
                             kSubprocRoutineReadyMessage);
}

}  // namespace
}  // namespace diagnostics
