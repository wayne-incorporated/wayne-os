// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_FINGERPRINT_FINGERPRINT_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_FINGERPRINT_FINGERPRINT_H_

#include <memory>
#include <string>
#include <vector>

#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

struct FingerprintPixel {
  FingerprintPixel(uint8_t value, uint16_t x, uint16_t y)
      : value(value), x(x), y(y) {}

  bool operator<(const FingerprintPixel& other) const {
    return value < other.value;
  }

  uint8_t value;
  uint16_t x;
  uint16_t y;
};

struct FingerprintPixelMedian {
  uint8_t cb_type1_lower;
  uint8_t cb_type1_upper;
  uint8_t cb_type2_lower;
  uint8_t cb_type2_upper;
  uint8_t icb_type1_lower;
  uint8_t icb_type1_upper;
  uint8_t icb_type2_lower;
  uint8_t icb_type2_upper;
};

struct FingerprintZone {
  uint32_t x1;
  uint32_t y1;
  uint32_t x2;
  uint32_t y2;
};

struct FingerprintParameter {
  uint32_t max_dead_pixels;
  uint32_t max_dead_pixels_in_detect_zone;
  uint32_t max_pixel_dev;
  uint32_t max_error_reset_pixels;
  uint32_t max_reset_pixel_dev;
  FingerprintPixelMedian pixel_median;
  std::vector<FingerprintZone> detect_zones;
};

class FingerprintRoutine final : public DiagnosticRoutineWithStatus {
 public:
  explicit FingerprintRoutine(Context* context, FingerprintParameter params);
  FingerprintRoutine(const FingerprintRoutine&) = delete;
  FingerprintRoutine& operator=(const FingerprintRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~FingerprintRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void RunNextStep();
  void ExamineCheckerboardFrame(
      ash::cros_healthd::mojom::FingerprintFrameResultPtr result,
      const std::optional<std::string>& err);
  void ExamineResetFrame(
      ash::cros_healthd::mojom::FingerprintFrameResultPtr result,
      const std::optional<std::string>& err);
  void CalculateBadPixel(const std::vector<FingerprintPixel>& pixels,
                         uint8_t median,
                         uint32_t max_deviation,
                         uint32_t* bad_pixel,
                         uint32_t* dead_pixel_in_detect_zone);
  bool CheckCheckerboardThreshold(uint8_t median_type1,
                                  uint8_t median_type2,
                                  uint32_t dead_pixel,
                                  uint32_t dead_pixel_in_detect_zone);
  bool CheckResetTestThreshold(uint32_t error_reset_pixel);

  // Context object used to communicate with the executor.
  Context* context_;

  // Fingerprint routine parameters.
  FingerprintParameter params_;

  enum TestStep {
    kInitialize = 0,
    kCheckerboardTest = 1,
    kInvertedCheckerboardTest = 2,
    kResetTest = 3,
    kComplete = 4,  // Should be the last one. New step should be added before
                    // it.
  };

  TestStep step_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_FINGERPRINT_FINGERPRINT_H_
