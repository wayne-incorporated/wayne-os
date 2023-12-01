// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/routines/simple_routine.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Test data.
constexpr auto kExpectedStatus = mojom::DiagnosticRoutineStatusEnum::kPassed;
constexpr char kExpectedStatusMessage[] = "This is a status message!";

// POD struct for ReportProgressPercentTest.
struct ReportProgressPercentTestParams {
  mojom::DiagnosticRoutineStatusEnum status;
  uint32_t expected_progress_percent;
};

// Holds the output from FakeRoutineTask in base::Value form, as well as the
// expected JSON output SimpleRoutine will generate from the base::Value.
struct FakeExpectedOutput {
  base::Value::Dict output_dict;
  std::string json;
};

// Generates expected output for a simple routine in both string and base::Value
// formats.
FakeExpectedOutput GetFakeExpectedOutput() {
  base::Value::Dict output_dict;
  output_dict.Set("testOutput", "testValue");
  std::string json;
  base::JSONWriter::Write(output_dict, &json);
  FakeExpectedOutput fake_output;
  fake_output.output_dict = std::move(output_dict);
  fake_output.json = std::move(json);
  return fake_output;
}

// Task for a SimpleRoutine to run.
void FakeRoutineTask(mojom::DiagnosticRoutineStatusEnum status_in,
                     const std::string& status_message_in,
                     base::Value::Dict output_dict_in,
                     SimpleRoutine::RoutineResultCallback callback) {
  std::move(callback).Run({
      .status = status_in,
      .status_message = status_message_in,
      .output_dict = std::move(output_dict_in),
  });
}

class SimpleRoutineTest : public testing::Test {
 protected:
  SimpleRoutineTest() = default;
  SimpleRoutineTest(const SimpleRoutineTest&) = delete;
  SimpleRoutineTest& operator=(const SimpleRoutineTest&) = delete;

  DiagnosticRoutine* routine() { return routine_.get(); }

  mojom::RoutineUpdate* update() { return &update_; }

  void CreateRoutine(base::Value::Dict desired_output,
                     mojom::DiagnosticRoutineStatusEnum desired_status =
                         mojom::DiagnosticRoutineStatusEnum::kFailed,
                     const std::string& desired_status_message = "") {
    routine_ = std::make_unique<SimpleRoutine>(base::BindOnce(
        &FakeRoutineTask, desired_status, std::move(desired_status_message),
        std::move(desired_output)));
  }

  void RunRoutineAndCollectUpdate(bool include_output) {
    routine_->Start();

    // Since the SimpleRoutine has finished by the time Start() returns, there
    // is no need to wait.
    routine_->PopulateStatusUpdate(&update_, include_output);
  }

 private:
  std::unique_ptr<SimpleRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

// Test that we can run a noninteractive routine and retrieve its status update.
TEST_F(SimpleRoutineTest, RunAndRetrieveStatusUpdate) {
  auto output = GetFakeExpectedOutput();
  CreateRoutine(std::move(output.output_dict), kExpectedStatus,
                kExpectedStatusMessage);

  RunRoutineAndCollectUpdate(/*include_output=*/true);

  VerifyNonInteractiveUpdate(update()->routine_update_union, kExpectedStatus,
                             kExpectedStatusMessage);
  EXPECT_EQ(GetStringFromValidReadOnlySharedMemoryMapping(
                std::move(update()->output)),
            output.json);
  EXPECT_EQ(update()->progress_percent, 100);
}

// Test that retrieving a status update with the include_output flag set to
// false doesn't return any output.
TEST_F(SimpleRoutineTest, NoOutputReturned) {
  auto output = GetFakeExpectedOutput();
  CreateRoutine(std::move(output.output_dict), kExpectedStatus,
                kExpectedStatusMessage);

  RunRoutineAndCollectUpdate(/*include_output=*/false);

  VerifyNonInteractiveUpdate(update()->routine_update_union, kExpectedStatus,
                             kExpectedStatusMessage);
  EXPECT_FALSE(update()->output.is_valid());
  EXPECT_EQ(update()->progress_percent, 100);
}

// Test that calling resume doesn't crash.
TEST_F(SimpleRoutineTest, Resume) {
  auto output = GetFakeExpectedOutput();
  CreateRoutine(std::move(output.output_dict));

  routine()->Resume();
}

// Test that calling cancel doesn't crash.
TEST_F(SimpleRoutineTest, Cancel) {
  auto output = GetFakeExpectedOutput();
  CreateRoutine(std::move(output.output_dict));

  routine()->Cancel();
}

// Test that we can retrieve the status of a simple routine.
TEST_F(SimpleRoutineTest, GetStatus) {
  auto output = GetFakeExpectedOutput();
  CreateRoutine(std::move(output.output_dict));

  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

// Tests that progress is reported correctly for each possible status.
//
// This is a parameterized test with the following parameters (accessed
// through the ReportProgressPercentTestParams POD struct):
// * |status| - status reported by the routine's task.
// * |expected_progress_percent| - expected value for the routine's progress
//                                 percent.
class ReportProgressPercentTest
    : public SimpleRoutineTest,
      public testing::WithParamInterface<ReportProgressPercentTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  ReportProgressPercentTestParams params() const { return GetParam(); }
};

// Test that we can parse the given uname response for CPU architecture.
TEST_P(ReportProgressPercentTest, ReportProgressPercent) {
  auto output = GetFakeExpectedOutput();
  CreateRoutine(std::move(output.output_dict), params().status,
                kExpectedStatusMessage);

  RunRoutineAndCollectUpdate(/*include_output=*/true);

  VerifyNonInteractiveUpdate(update()->routine_update_union, params().status,
                             kExpectedStatusMessage);
  EXPECT_EQ(GetStringFromValidReadOnlySharedMemoryMapping(
                std::move(update()->output)),
            output.json);
  EXPECT_EQ(update()->progress_percent, params().expected_progress_percent);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    ReportProgressPercentTest,
    testing::Values(
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kReady, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kRunning, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kWaiting, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kPassed, 100},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kFailed, 100},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kError, 100},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kCancelled, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kFailedToStart, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kRemoved, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kCancelling, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kUnsupported, 0},
        ReportProgressPercentTestParams{
            mojom::DiagnosticRoutineStatusEnum::kNotRun, 0}));

}  // namespace
}  // namespace diagnostics
