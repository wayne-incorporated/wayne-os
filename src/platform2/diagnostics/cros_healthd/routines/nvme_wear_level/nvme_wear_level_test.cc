// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/base64.h>
#include <base/check.h>
#include <debugd/dbus-proxy-mocks.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/routines/nvme_wear_level/nvme_wear_level.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using OnceStringCallback = base::OnceCallback<void(const std::string& result)>;
using OnceErrorCallback = base::OnceCallback<void(brillo::Error* error)>;
using ::testing::_;
using ::testing::StrictMock;
using ::testing::WithArg;

constexpr uint32_t kThreshold50 = 50;

constexpr uint8_t kWearLevel4[] = {0, 0, 0, 0, 0, 4, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0};
constexpr uint8_t kWearLevel70[] = {0, 0, 0, 0, 0, 70, 0, 0,
                                    0, 0, 0, 0, 0, 0,  0, 0};

// 8-byte data with wear level 4.
constexpr uint8_t kEightByteWearLevel4[] = {0, 0, 0, 0, 0, 4, 0, 0};

// Invalid base64 encoded data. Length of encoded data must divide by 4.
constexpr char kInvaildWearLevel[] = "AAAAAAAAAAAAAAAAAAA";

class NvmeWearLevelRoutineTest : public testing::Test {
 protected:
  NvmeWearLevelRoutineTest() = default;
  NvmeWearLevelRoutineTest(const NvmeWearLevelRoutineTest&) = delete;
  NvmeWearLevelRoutineTest& operator=(const NvmeWearLevelRoutineTest&) = delete;

  DiagnosticRoutine* routine() { return routine_.get(); }

  void CreateWearLevelRoutine(
      const std::optional<uint32_t>& wear_level_threshold) {
    routine_ = std::make_unique<NvmeWearLevelRoutine>(&debugd_proxy_,
                                                      wear_level_threshold);
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
  std::unique_ptr<NvmeWearLevelRoutine> routine_;
};

// Tests that the NvmeWearLevel routine passes if wear level less than
// threshold.
TEST_F(NvmeWearLevelRoutineTest, Pass) {
  const std::string kNvmeRawOutput(std::begin(kWearLevel4),
                                   std::end(kWearLevel4));
  std::string nvme_encoded_output;
  base::Base64Encode(kNvmeRawOutput, &nvme_encoded_output);

  CreateWearLevelRoutine(kThreshold50);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeWearLevelRoutine::kNvmeLogPageId,
                           NvmeWearLevelRoutine::kNvmeLogDataLength,
                           NvmeWearLevelRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));

  EXPECT_EQ(routine()->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  VerifyNonInteractiveUpdate(
      RunRoutineAndWaitForExit()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kPassed,
      NvmeWearLevelRoutine::kNvmeWearLevelRoutineSuccess);
}

// Tests that the NvmeWearLevel routine fails if wear level larger than or equal
// to threshold.
TEST_F(NvmeWearLevelRoutineTest, HighWearLevel) {
  const std::string kNvmeRawOutput(std::begin(kWearLevel70),
                                   std::end(kWearLevel70));
  std::string nvme_encoded_output;
  base::Base64Encode(kNvmeRawOutput, &nvme_encoded_output);

  CreateWearLevelRoutine(kThreshold50);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeWearLevelRoutine::kNvmeLogPageId,
                           NvmeWearLevelRoutine::kNvmeLogDataLength,
                           NvmeWearLevelRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             NvmeWearLevelRoutine::kNvmeWearLevelRoutineFailed);
}

// Tests that the NvmeWearLevel routine fails if threshold exceeds 100.
TEST_F(NvmeWearLevelRoutineTest, InvalidThreshold) {
  const uint32_t kThreshold105 = 105;
  CreateWearLevelRoutine(kThreshold105);
  VerifyNonInteractiveUpdate(
      RunRoutineAndWaitForExit()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeWearLevelRoutine::kNvmeWearLevelRoutineThresholdError);
}

// Tests that the NvmeWearLevel routine fails if threshold is null.
TEST_F(NvmeWearLevelRoutineTest, NullThreshold) {
  const std::optional<uint32_t> kThresholdNull = std::nullopt;
  CreateWearLevelRoutine(kThresholdNull);
  VerifyNonInteractiveUpdate(
      RunRoutineAndWaitForExit()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeWearLevelRoutine::kNvmeWearLevelRoutineThresholdError);
}

// Tests that the NvmeWearLevel routine fails if wear level is invalid.
TEST_F(NvmeWearLevelRoutineTest, InvalidWearLevel) {
  CreateWearLevelRoutine(kThreshold50);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeWearLevelRoutine::kNvmeLogPageId,
                           NvmeWearLevelRoutine::kNvmeLogDataLength,
                           NvmeWearLevelRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(kInvaildWearLevel);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutineAndWaitForExit()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeWearLevelRoutine::kNvmeWearLevelRoutineGetInfoError);
}

// Tests that the NvmeWearLevel routine fails if size of return data is not
// equal to required length.
TEST_F(NvmeWearLevelRoutineTest, InvalidLength) {
  const std::string kNvmeRawOutput(std::begin(kEightByteWearLevel4),
                                   std::end(kEightByteWearLevel4));
  std::string nvme_encoded_output;
  base::Base64Encode(kNvmeRawOutput, &nvme_encoded_output);

  CreateWearLevelRoutine(kThreshold50);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeWearLevelRoutine::kNvmeLogPageId,
                           NvmeWearLevelRoutine::kNvmeLogDataLength,
                           NvmeWearLevelRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutineAndWaitForExit()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeWearLevelRoutine::kNvmeWearLevelRoutineGetInfoError);
}

// Tests that the NvmeWearLevel routine fails if debugd returns with an error.
TEST_F(NvmeWearLevelRoutineTest, DebugdError) {
  const char kDebugdErrorMessage[] = "Debugd mock error for testing";
  const brillo::ErrorPtr kError =
      brillo::Error::Create(FROM_HERE, "", "", kDebugdErrorMessage);
  CreateWearLevelRoutine(kThreshold50);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeWearLevelRoutine::kNvmeLogPageId,
                           NvmeWearLevelRoutine::kNvmeLogDataLength,
                           NvmeWearLevelRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<4>([&](OnceErrorCallback callback) {
        std::move(callback).Run(kError.get());
      }));
  VerifyNonInteractiveUpdate(RunRoutineAndWaitForExit()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kDebugdErrorMessage);
}

}  // namespace
}  // namespace diagnostics
