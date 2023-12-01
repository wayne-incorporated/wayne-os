// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/fingerprint/fingerprint.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/logging.h>

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

uint8_t CalculateMedian(const std::vector<FingerprintPixel>& pixels) {
  // The input should be sorted before calling this function.
  auto size = pixels.size();
  if (size % 2 == 0) {
    return (static_cast<uint16_t>(pixels[size / 2 - 1].value) +
            pixels[size / 2].value) /
           2;
  } else {
    return pixels[size / 2].value;
  }
}

bool IsInDetectZone(const FingerprintPixel& pixel,
                    const std::vector<FingerprintZone>& detect_zones) {
  for (const auto& zone : detect_zones) {
    if (pixel.x >= zone.x1 && pixel.x <= zone.x2 && pixel.y >= zone.y1 &&
        pixel.y <= zone.y2) {
      return true;
    }
  }
  return false;
}

}  // namespace

FingerprintRoutine::FingerprintRoutine(Context* context,
                                       FingerprintParameter params)
    : context_(context),
      params_(std::move(params)),
      step_(TestStep::kInitialize) {}

FingerprintRoutine::~FingerprintRoutine() = default;

void FingerprintRoutine::Start() {
  RunNextStep();
}

void FingerprintRoutine::Resume() {}

void FingerprintRoutine::Cancel() {}

void FingerprintRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                              bool include_output) {
  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = GetStatus();
  update->status_message = GetStatusMessage();
  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  response->progress_percent = step_ * 100 / TestStep::kComplete;
}

bool FingerprintRoutine::CheckCheckerboardThreshold(
    uint8_t median_type1,
    uint8_t median_type2,
    uint32_t dead_pixel,
    uint32_t dead_pixel_in_detect_zone) {
  if (step_ == TestStep::kCheckerboardTest) {
    if (median_type1 < params_.pixel_median.cb_type1_lower ||
        median_type1 > params_.pixel_median.cb_type1_upper ||
        median_type2 < params_.pixel_median.cb_type2_lower ||
        median_type2 > params_.pixel_median.cb_type2_upper) {
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                   "Checkerboard median deviation too large.");
      return false;
    }
  } else if (step_ == TestStep::kInvertedCheckerboardTest) {
    if (median_type1 < params_.pixel_median.icb_type1_lower ||
        median_type1 > params_.pixel_median.icb_type1_upper ||
        median_type2 < params_.pixel_median.icb_type2_lower ||
        median_type2 > params_.pixel_median.icb_type2_upper) {
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                   "Inverted checkerboard median deviation too large.");
      return false;
    }
  } else {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 "Unexpected flow in checkerboard test.");
    return false;
  }

  if (dead_pixel > params_.max_dead_pixels) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Dead pixel count exceed threshold.");
    return false;
  }

  if (dead_pixel_in_detect_zone > params_.max_dead_pixels_in_detect_zone) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Dead pixel count in detect zone exceed threshold.");
    return false;
  }

  return true;
}

void FingerprintRoutine::CalculateBadPixel(
    const std::vector<FingerprintPixel>& pixels,
    uint8_t median,
    uint32_t max_deviation,
    uint32_t* bad_pixel,
    uint32_t* dead_pixel_in_detect_zone) {
  for (const auto& pixel : pixels) {
    if (std::max(pixel.value, median) - std::min(pixel.value, median) >
        max_deviation) {
      if (bad_pixel) {
        ++(*bad_pixel);
      }
      if (dead_pixel_in_detect_zone &&
          IsInDetectZone(pixel, params_.detect_zones)) {
        ++(*dead_pixel_in_detect_zone);
      }
    }
  }
}

void FingerprintRoutine::ExamineCheckerboardFrame(
    mojom::FingerprintFrameResultPtr result,
    const std::optional<std::string>& err) {
  if (err.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed, err.value());
    return;
  }

  if (!result) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Failed to get frame result.");
    return;
  }

  // Sort pixel according to parity.
  // Type 1: (i + j) % 2 == 0.
  // Type 2: (i + j) % 2 == 1.
  std::vector<FingerprintPixel> pixels_type1;
  std::vector<FingerprintPixel> pixels_type2;
  for (int i = 0; i < result->height; ++i) {
    for (int j = 0; j < result->width; ++j) {
      if ((i + j) % 2 == 0) {
        pixels_type1.emplace_back(result->frame[i * result->height + j], i, j);
      } else {
        pixels_type2.emplace_back(result->frame[i * result->height + j], i, j);
      }
    }
  }
  std::sort(pixels_type1.begin(), pixels_type1.end());
  std::sort(pixels_type2.begin(), pixels_type2.end());

  uint8_t median_type1 = CalculateMedian(pixels_type1);
  uint8_t median_type2 = CalculateMedian(pixels_type2);
  uint32_t dead_pixel = 0;
  uint32_t dead_pixel_in_detect_zone = 0;
  CalculateBadPixel(pixels_type1, median_type1, params_.max_pixel_dev,
                    &dead_pixel, &dead_pixel_in_detect_zone);
  CalculateBadPixel(pixels_type2, median_type2, params_.max_pixel_dev,
                    &dead_pixel, &dead_pixel_in_detect_zone);
  LOG(INFO) << "median_type1 = " << static_cast<uint32_t>(median_type1);
  LOG(INFO) << "median_type2 = " << static_cast<uint32_t>(median_type2);
  LOG(INFO) << "dead_pixel = " << dead_pixel;
  LOG(INFO) << "dead_pixel_in_detect_zone = " << dead_pixel_in_detect_zone;

  if (!CheckCheckerboardThreshold(median_type1, median_type2, dead_pixel,
                                  dead_pixel_in_detect_zone)) {
    return;
  }

  RunNextStep();
}

bool FingerprintRoutine::CheckResetTestThreshold(uint32_t error_reset_pixel) {
  if (error_reset_pixel > params_.max_error_reset_pixels) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Error reset pixel count exceed threshold.");
    return false;
  }

  return true;
}

void FingerprintRoutine::ExamineResetFrame(
    mojom::FingerprintFrameResultPtr result,
    const std::optional<std::string>& err) {
  if (err.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed, err.value());
    return;
  }

  if (!result) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Failed to get frame result.");
    return;
  }

  // According to the spec, we should examine reset frame column by column.
  uint32_t error_reset_pixel = 0;
  for (int j = 0; j < result->width; ++j) {
    std::vector<FingerprintPixel> pixels;
    for (int i = 0; i < result->height; ++i) {
      pixels.emplace_back(result->frame[i * result->width + j], i, j);
    }
    std::sort(pixels.begin(), pixels.end());

    uint8_t median = CalculateMedian(pixels);
    CalculateBadPixel(pixels, median, params_.max_reset_pixel_dev,
                      &error_reset_pixel, nullptr);
  }
  LOG(INFO) << "error_reset_pixel = " << error_reset_pixel;

  if (!CheckResetTestThreshold(error_reset_pixel)) {
    return;
  }

  RunNextStep();
}

void FingerprintRoutine::RunNextStep() {
  step_ = static_cast<TestStep>(static_cast<int>(step_) + 1);

  switch (step_) {
    case TestStep::kInitialize:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                   "Unexpected fingerprint diagnostic flow.");
      break;
    case TestStep::kCheckerboardTest:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
      context_->executor()->GetFingerprintFrame(
          mojom::FingerprintCaptureType::kCheckerboardTest,
          base::BindOnce(&FingerprintRoutine::ExamineCheckerboardFrame,
                         base::Unretained(this)));
      break;
    case TestStep::kInvertedCheckerboardTest:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
      context_->executor()->GetFingerprintFrame(
          mojom::FingerprintCaptureType::kInvertedCheckerboardTest,
          base::BindOnce(&FingerprintRoutine::ExamineCheckerboardFrame,
                         base::Unretained(this)));
      break;
    case TestStep::kResetTest:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
      context_->executor()->GetFingerprintFrame(
          mojom::FingerprintCaptureType::kResetTest,
          base::BindOnce(&FingerprintRoutine::ExamineResetFrame,
                         base::Unretained(this)));
      break;
    case TestStep::kComplete:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed, "");
      break;
  }
}

}  // namespace diagnostics
