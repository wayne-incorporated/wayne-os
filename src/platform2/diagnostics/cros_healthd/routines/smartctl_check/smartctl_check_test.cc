// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/base64.h>
#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <debugd/dbus-proxy-mocks.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/routines/smartctl_check/smartctl_check.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using OnceStringCallback = base::OnceCallback<void(const std::string& result)>;
using OnceErrorCallback = base::OnceCallback<void(brillo::Error* error)>;
using ::testing::_;
using ::testing::StrictMock;
using ::testing::WithArg;

constexpr char kSmartctlOutputFormat[] =
    "\nCritical Warning: %#02x\nAvailable Spare: %d%%\nAvailable Spare "
    "Threshold: %d%%\nPercentage Used: %d%%";

std::string GetFakeSmartctlOutput(const int available_spare,
                                  const int available_spare_threshold,
                                  const int percentage_used,
                                  const int critical_warning) {
  return base::StringPrintf(kSmartctlOutputFormat, critical_warning,
                            available_spare, available_spare_threshold,
                            percentage_used);
}

void VerifyOutput(mojo::ScopedHandle handle,
                  const int expected_available_spare,
                  const int expected_available_spare_threshold,
                  const int expected_percentage_used,
                  const int expected_percentage_used_threshold,
                  const int expected_critical_warning) {
  const auto& json_output = base::JSONReader::Read(
      GetStringFromValidReadOnlySharedMemoryMapping(std::move(handle)));
  const auto& output_dict = json_output->GetIfDict();
  ASSERT_NE(output_dict, nullptr);

  const auto& result_details = output_dict->FindDict("resultDetails");
  ASSERT_NE(result_details, nullptr);
  ASSERT_EQ(result_details->FindInt("availableSpare"),
            expected_available_spare);
  ASSERT_EQ(result_details->FindInt("availableSpareThreshold"),
            expected_available_spare_threshold);
  ASSERT_EQ(result_details->FindInt("percentageUsed"),
            expected_percentage_used);
  ASSERT_EQ(result_details->FindInt("inputPercentageUsedThreshold"),
            expected_percentage_used_threshold);
  ASSERT_EQ(result_details->FindInt("criticalWarning"),
            expected_critical_warning);
}

class SmartctlCheckRoutineTest : public testing::Test {
 protected:
  SmartctlCheckRoutineTest() = default;
  SmartctlCheckRoutineTest(const SmartctlCheckRoutineTest&) = delete;
  SmartctlCheckRoutineTest& operator=(const SmartctlCheckRoutineTest&) = delete;

  DiagnosticRoutine* routine() { return routine_.get(); }

  void CreateSmartctlCheckRoutine(
      const std::optional<uint32_t>& percentage_used_threshold) {
    routine_ = std::make_unique<SmartctlCheckRoutine>(
        &debugd_proxy_, percentage_used_threshold);
  }

  mojom::RoutineUpdatePtr RunRoutineAndWaitForExit() {
    DCHECK(routine_);
    mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                                mojom::RoutineUpdateUnionPtr()};

    routine_->Start();
    routine_->PopulateStatusUpdate(&update, true);
    return mojom::RoutineUpdate::New(update.progress_percent,
                                     std::move(update.output),
                                     std::move(update.routine_update_union));
  }

  StrictMock<org::chromium::debugdProxyMock> debugd_proxy_;

 private:
  std::unique_ptr<SmartctlCheckRoutine> routine_;
};

// Tests that the SmartctlCheck routine passes with input.
TEST_F(SmartctlCheckRoutineTest, PassWithInput) {
  int available_spare = 100;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 255;
  int critical_warning = 0x00;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kSmartctlCheckRoutineSuccess);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine passes without input.
TEST_F(SmartctlCheckRoutineTest, PassWithoutInput) {
  int available_spare = 100;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int critical_warning = 0x00;

  CreateSmartctlCheckRoutine(std::nullopt);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kSmartctlCheckRoutineSuccess);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               SmartctlCheckRoutine::kPercentageUsedMax, critical_warning);
}

// Tests that the SmartctlCheck routine fails if input threshold is invalid.
TEST_F(SmartctlCheckRoutineTest, InvalidPercentageUsedThreshold) {
  CreateSmartctlCheckRoutine(256);
  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kSmartctlCheckRoutineThresholdError);
}

// Tests that the SmartctlCheck routine fails if
// - available_spare check fails.
TEST_F(SmartctlCheckRoutineTest, AvailableSpareCheckFailed) {
  int available_spare = 1;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 100;
  int critical_warning = 0x00;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if
// - percentage_used check fails.
TEST_F(SmartctlCheckRoutineTest, PercentageUsedCheckFailed) {
  int available_spare = 100;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 5;
  int critical_warning = 0x00;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if
// - critical_warning check fails.
TEST_F(SmartctlCheckRoutineTest, CriticalWarningCheckFailed) {
  int available_spare = 100;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 100;
  int critical_warning = 0x0F;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if
// - available_spare check fails.
// - percentage_used check fails.
TEST_F(SmartctlCheckRoutineTest, AvailableSpareAndPercentageUsedCheckFailed) {
  int available_spare = 1;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 5;
  int critical_warning = 0x00;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if
// - available_spare check fails.
// - critical_warning check fails.
TEST_F(SmartctlCheckRoutineTest, AvailableSpareAndCriticalWarningCheckFailed) {
  int available_spare = 1;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 100;
  int critical_warning = 0x0F;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if
// - percentage_used check fails.
// - critical_warning check fails.
TEST_F(SmartctlCheckRoutineTest, PercentageUsedCheckAndCriticalWarningFailed) {
  int available_spare = 100;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 5;
  int critical_warning = 0x0F;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if
// - available_spare check fails.
// - percentage_used check fails.
// - critical_warning check fails.
TEST_F(SmartctlCheckRoutineTest, AllChecksFailed) {
  int available_spare = 1;
  int available_spare_threshold = 5;
  int percentage_used = 50;
  int percentage_used_threshold = 5;
  int critical_warning = 0x0F;

  CreateSmartctlCheckRoutine(percentage_used_threshold);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(
            GetFakeSmartctlOutput(available_spare, available_spare_threshold,
                                  percentage_used, critical_warning));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineCheckFailed);
  VerifyOutput(std::move(routine_update->output), available_spare,
               available_spare_threshold, percentage_used,
               percentage_used_threshold, critical_warning);
}

// Tests that the SmartctlCheck routine fails if debugd proxy returns
// invalid data.
TEST_F(SmartctlCheckRoutineTest, InvalidDebugdData) {
  CreateSmartctlCheckRoutine(std::nullopt);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<1>(
          [&](OnceStringCallback callback) { std::move(callback).Run(""); }));

  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kSmartctlCheckRoutineFailedToParse);
}

// Tests that the SmartctlCheck routine returns error if debugd returns with an
// error.
TEST_F(SmartctlCheckRoutineTest, DebugdError) {
  const char kDebugdErrorMessage[] = "Debugd mock error for testing";
  const brillo::ErrorPtr kError =
      brillo::Error::Create(FROM_HERE, "", "", kDebugdErrorMessage);
  CreateSmartctlCheckRoutine(std::nullopt);
  EXPECT_CALL(debugd_proxy_, SmartctlAsync("attributes", _, _, _))
      .WillOnce(WithArg<2>([&](OnceErrorCallback callback) {
        std::move(callback).Run(kError.get());
      }));
  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kSmartctlCheckRoutineDebugdError);
}

}  // namespace
}  // namespace diagnostics
