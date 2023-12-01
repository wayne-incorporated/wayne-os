// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <debugd/dbus-proxy-mocks.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/emmc_lifetime/emmc_lifetime.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/debugd_constants.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using OnceStringCallback = base::OnceCallback<void(const std::string& result)>;
using OnceErrorCallback = base::OnceCallback<void(brillo::Error* error)>;
using ::testing::_;
using ::testing::StrictMock;
using ::testing::WithArg;

constexpr char kMmcOutputFormat[] =
    "\nDevice life time estimation type B [DEVICE_LIFE_TIME_EST_TYP_B: "
    "%#02x]\nDevice life time estimation type A [DEVICE_LIFE_TIME_EST_TYP_A: "
    "%#02x]\nPre EOL information [PRE_EOL_INFO: %#02x]\n";

std::string GetFakeMmcOutput(const uint32_t pre_eol_info,
                             const uint32_t device_life_time_est_typ_a,
                             const uint32_t device_life_time_est_typ_b) {
  return base::StringPrintf(kMmcOutputFormat, device_life_time_est_typ_b,
                            device_life_time_est_typ_a, pre_eol_info);
}

void VerifyOutput(mojo::ScopedHandle handle,
                  const uint32_t expected_pre_eol_info,
                  const uint32_t expected_device_life_time_est_typ_a,
                  const uint32_t expected_device_life_time_est_typ_b) {
  ASSERT_TRUE(handle->is_valid());
  const auto& json_output = base::JSONReader::Read(
      GetStringFromValidReadOnlySharedMemoryMapping(std::move(handle)));
  const auto& output_dict = json_output->GetIfDict();
  ASSERT_NE(output_dict, nullptr);

  const auto& result_details = output_dict->FindDict("resultDetails");
  ASSERT_NE(result_details, nullptr);
  ASSERT_EQ(result_details->FindInt("PRE_EOL_INFO"), expected_pre_eol_info);
  ASSERT_EQ(result_details->FindInt("DEVICE_LIFE_TIME_EST_TYP_A"),
            expected_device_life_time_est_typ_a);
  ASSERT_EQ(result_details->FindInt("DEVICE_LIFE_TIME_EST_TYP_B"),
            expected_device_life_time_est_typ_b);
}

class EmmcLifetimeRoutineTest : public testing::Test {
 protected:
  EmmcLifetimeRoutineTest() = default;
  EmmcLifetimeRoutineTest(const EmmcLifetimeRoutineTest&) = delete;
  EmmcLifetimeRoutineTest& operator=(const EmmcLifetimeRoutineTest&) = delete;

  DiagnosticRoutine* routine() { return routine_.get(); }

  void CreateEmmcLifetimeRoutine() {
    routine_ = std::make_unique<EmmcLifetimeRoutine>(&debugd_proxy_);
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
  std::unique_ptr<EmmcLifetimeRoutine> routine_;
};

// Tests that the EmmcLifetime routine passes if PRE_EOL_LIFETIME is normal
// (0x01).
TEST_F(EmmcLifetimeRoutineTest, Pass) {
  uint32_t pre_eol_info = 0x01;
  uint32_t device_life_time_est_typ_a = 0x0A;
  uint32_t device_life_time_est_typ_b = 0x06;

  CreateEmmcLifetimeRoutine();
  EXPECT_CALL(debugd_proxy_, MmcAsync(kMmcExtcsdReadOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(GetFakeMmcOutput(pre_eol_info,
                                                 device_life_time_est_typ_a,
                                                 device_life_time_est_typ_b));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kEmmcLifetimeRoutineSuccess);
  VerifyOutput(std::move(routine_update->output), pre_eol_info,
               device_life_time_est_typ_a, device_life_time_est_typ_b);
}

// Tests that the EmmcLifetime routine fails if PRE_EOL_LIFETIME is not normal
// (0x01).
TEST_F(EmmcLifetimeRoutineTest, PreEolLifetimeNotNormal) {
  uint32_t pre_eol_info = 0x02;
  uint32_t device_life_time_est_typ_a = 0x05;
  uint32_t device_life_time_est_typ_b = 0x0B;

  CreateEmmcLifetimeRoutine();
  EXPECT_CALL(debugd_proxy_, MmcAsync(kMmcExtcsdReadOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(GetFakeMmcOutput(pre_eol_info,
                                                 device_life_time_est_typ_a,
                                                 device_life_time_est_typ_b));
      }));
  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  const auto& routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kEmmcLifetimeRoutinePreEolInfoAbnormalError);
  VerifyOutput(std::move(routine_update->output), pre_eol_info,
               device_life_time_est_typ_a, device_life_time_est_typ_b);
}

// Tests that the EmmcLifetime routine fails if debugd proxy returns invalid
// data.
TEST_F(EmmcLifetimeRoutineTest, InvalidDebugdData) {
  CreateEmmcLifetimeRoutine();
  EXPECT_CALL(debugd_proxy_, MmcAsync(kMmcExtcsdReadOption, _, _, _))
      .WillOnce(WithArg<1>(
          [&](OnceStringCallback callback) { std::move(callback).Run(""); }));

  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kEmmcLifetimeRoutineParseError);
}

// Tests that the EmmcLifetime routine fails if debugd returns with an error.
TEST_F(EmmcLifetimeRoutineTest, DebugdError) {
  const char kDebugdErrorMessage[] = "Debugd mock error for testing";
  const brillo::ErrorPtr kError =
      brillo::Error::Create(FROM_HERE, "", "", kDebugdErrorMessage);
  CreateEmmcLifetimeRoutine();
  EXPECT_CALL(debugd_proxy_, MmcAsync(kMmcExtcsdReadOption, _, _, _))
      .WillOnce(WithArg<2>([&](OnceErrorCallback callback) {
        std::move(callback).Run(kError.get());
      }));
  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kEmmcLifetimeRoutineDebugdError);
}

}  // namespace
}  // namespace diagnostics
