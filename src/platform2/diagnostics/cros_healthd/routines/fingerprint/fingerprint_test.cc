// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/fingerprint/fingerprint.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;

class FingerprintRoutineTest : public testing::Test {
 protected:
  FingerprintRoutineTest() = default;
  FingerprintRoutineTest(const FingerprintRoutineTest&) = delete;
  FingerprintRoutineTest& operator=(const FingerprintRoutineTest&) = delete;

  FingerprintParameter CreateDefaultFingerprintParameter() {
    FingerprintParameter params;

    params.max_dead_pixels = 1;
    params.max_dead_pixels_in_detect_zone = 1;
    params.max_pixel_dev = 5;
    params.max_error_reset_pixels = 1;
    params.max_reset_pixel_dev = 5;
    params.pixel_median.cb_type1_lower = 3;
    params.pixel_median.cb_type1_upper = 5;
    params.pixel_median.cb_type2_lower = 11;
    params.pixel_median.cb_type2_upper = 13;
    params.pixel_median.icb_type1_lower = 3;
    params.pixel_median.icb_type1_upper = 5;
    params.pixel_median.icb_type2_lower = 11;
    params.pixel_median.icb_type2_upper = 13;
    params.detect_zones = {{/*x1=*/1, /*y1=*/3, /*x2=*/1, /*y2=*/3}};

    return params;
  }

  void CreateRoutine(FingerprintParameter params) {
    routine_ = std::make_unique<FingerprintRoutine>(mock_context(), params);
  }

  // Return the following 4*4 checkerboard frame.
  //
  //  1, 16,  2, 15,
  // 14,  3, 13,  4,
  //  5, 12,  6, 11,
  // 10,  7,  9,  8,
  //
  // Type-1 pixel values are: 1, 2, 3, 4, 5, 6, 7, 8
  //   - median: 4
  //   - max deviation: 4
  //
  // Type-2 pixel values are : 9, 10, 11, 12, 13, 14, 15, 16
  //   - median: 12
  //   - max deviation: 4
  //
  // The value in detect zone is "4" (type 1), so it's a good pixel.
  void SetExecutorCheckerboardFrameResponse(
      const std::optional<std::string>& err) {
    EXPECT_CALL(*mock_executor(),
                GetFingerprintFrame(
                    mojom::FingerprintCaptureType::kCheckerboardTest, _))
        .WillOnce(WithArg<1>(
            Invoke([=](mojom::Executor::GetFingerprintFrameCallback callback) {
              mojom::FingerprintFrameResult result;
              result.width = 4;
              result.height = 4;
              result.frame = {1, 16, 2, 15, 14, 3, 13, 4,
                              5, 12, 6, 11, 10, 7, 9,  8};

              std::move(callback).Run(result.Clone(), err);
            })));
  }

  // Return the following 4*4 inverted checkerboard frame.
  //
  //  1, 16,  2, 15,
  // 14,  3, 13,  4,
  //  5, 12,  6, 11,
  // 10,  7,  9,  8,
  //
  // Type-1 pixel values are: 1, 2, 3, 4, 5, 6, 7, 8
  //   - median: 4
  //   - max deviation: 4
  //
  // Type-2 pixel values are : 9, 10, 11, 12, 13, 14, 15, 16
  //   - median: 12
  //   - max deviation: 4
  void SetExecutorInvertedCheckerboardFrameResponse(
      const std::optional<std::string>& err) {
    EXPECT_CALL(
        *mock_executor(),
        GetFingerprintFrame(
            mojom::FingerprintCaptureType::kInvertedCheckerboardTest, _))
        .WillOnce(WithArg<1>(
            Invoke([=](mojom::Executor::GetFingerprintFrameCallback callback) {
              mojom::FingerprintFrameResult result;
              result.width = 4;
              result.height = 4;
              result.frame = {1, 16, 2, 15, 14, 3, 13, 4,
                              5, 12, 6, 11, 10, 7, 9,  8};

              std::move(callback).Run(result.Clone(), err);
            })));
  }

  // Return the following 5*1 reset test frame.
  //
  // Since it checks column by column, so we only need to fill one column.
  //
  // 1,
  // 2,
  // 3,
  // 4,
  // 5,
  //
  // The first column values are: 1, 2, 3, 4, 5
  //   - median: 3
  //   - max deviation: 2
  void SetExecutorResetTestFrameResponse(
      const std::optional<std::string>& err) {
    EXPECT_CALL(
        *mock_executor(),
        GetFingerprintFrame(mojom::FingerprintCaptureType::kResetTest, _))
        .WillOnce(WithArg<1>(
            Invoke([=](mojom::Executor::GetFingerprintFrameCallback callback) {
              mojom::FingerprintFrameResult result;
              result.width = 1;
              result.height = 5;
              result.frame = {1, 2, 3, 4, 5};

              std::move(callback).Run(result.Clone(), err);
            })));
  }

  MockContext* mock_context() { return &mock_context_; }
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  MockContext mock_context_;
  std::unique_ptr<FingerprintRoutine> routine_;
};

TEST_F(FingerprintRoutineTest, DefaultConstruction) {
  auto params = CreateDefaultFingerprintParameter();
  CreateRoutine(std::move(params));
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

TEST_F(FingerprintRoutineTest, ResponseErrorCase) {
  auto params = CreateDefaultFingerprintParameter();
  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse("err");

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, SuccessfulCase) {
  auto params = CreateDefaultFingerprintParameter();
  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);
  SetExecutorInvertedCheckerboardFrameResponse(/*err=*/std::nullopt);
  SetExecutorResetTestFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(FingerprintRoutineTest, CheckerboardDeadPixelsExceed) {
  auto params = CreateDefaultFingerprintParameter();
  // Modify the |params_.max_pixel_dev| to 1, so the dead pixel count will
  // exceed |params_.max_dead_pixels|. (Dead pixel count is 10.)
  params.max_pixel_dev = 1;
  params.max_dead_pixels = 1;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, CheckerboardType1MedianDevTooLarge) {
  auto params = CreateDefaultFingerprintParameter();
  // According to SetExecutorCheckerboardFrameResponse, the median is 4.
  params.pixel_median.cb_type1_lower = 1;
  params.pixel_median.cb_type1_upper = 2;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, CheckerboardType2MedianDevTooLarge) {
  auto params = CreateDefaultFingerprintParameter();
  // According to SetExecutorCheckerboardFrameResponse, the median is 12.
  params.pixel_median.cb_type2_lower = 1;
  params.pixel_median.cb_type2_upper = 2;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, InvertedCheckerboardType1MedianDevTooLarge) {
  auto params = CreateDefaultFingerprintParameter();
  // According to SetExecutorInvertedCheckerboardFrameResponse, the median is 4.
  params.pixel_median.icb_type1_lower = 1;
  params.pixel_median.icb_type1_upper = 2;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);
  SetExecutorInvertedCheckerboardFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, InvertedCheckerboardType2MedianDevTooLarge) {
  auto params = CreateDefaultFingerprintParameter();
  // According to SetExecutorInvertedCheckerboardFrameResponse, the median is
  // 12.
  params.pixel_median.icb_type1_lower = 1;
  params.pixel_median.icb_type1_upper = 2;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);
  SetExecutorInvertedCheckerboardFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, ResetTestErrorPixelsExceed) {
  auto params = CreateDefaultFingerprintParameter();
  // Modify the |params_.max_reset_pixel_dev| to 1, so the dead pixel count will
  // exceed |params_.max_error_reset_pixels|. (Error pixel count is 2.)
  params.max_error_reset_pixels = 1;
  params.max_reset_pixel_dev = 1;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);
  SetExecutorInvertedCheckerboardFrameResponse(/*err=*/std::nullopt);
  SetExecutorResetTestFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintRoutineTest, CheckerboardDeadPixelInDetectZone) {
  auto params = CreateDefaultFingerprintParameter();
  // Set the detect zone to {/*x1=*/3, /*y1=*/3, /*x2=*/3, /*y2=*/3}, and modify
  // the |params_.max_pixel_dev| to 1 to make the detect zone contain a dead
  // pixel.
  params.detect_zones = {{/*x1=*/3, /*y1=*/3, /*x2=*/3, /*y2=*/3}};
  params.max_pixel_dev = 1;

  CreateRoutine(std::move(params));
  SetExecutorCheckerboardFrameResponse(/*err=*/std::nullopt);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

}  // namespace
}  // namespace diagnostics
