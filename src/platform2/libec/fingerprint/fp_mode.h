// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_MODE_H_
#define LIBEC_FINGERPRINT_FP_MODE_H_

#include <ostream>

#include "base/types/cxx23_to_underlying.h"
#include <brillo/brillo_export.h>

namespace ec {

class BRILLO_EXPORT FpMode {
 public:
  enum class Mode : int {
    // NOTE: These values are used directly by UMA, so the values must not
    // be modified. New values should be added to the end (before kModeInvalid).
    kNone = 0,
    kDeepsleep,
    kFingerDown,
    kFingerUp,
    kCapture,
    kEnrollSession,
    kEnrollSessionFingerUp,
    kEnrollSessionEnrollImage,
    kEnrollImage,
    kMatch,
    kResetSensor,
    kDontChange,
    kSensorMaintenance,

    kModeInvalid = 13,

    kCaptureVendorFormat = kCapture,
    kCaptureSimpleImage = 14,
    kCapturePattern0 = 15,
    kCapturePattern1 = 16,
    kCaptureQualityTest = 17,
    kCaptureResetTest = 18,

    kMaxValue = kCaptureResetTest,  // must be last item
  };

  FpMode() = default;
  explicit FpMode(Mode mode) : mode_(mode) {}
  explicit FpMode(uint32_t mode);

  bool operator==(const FpMode& rhs) const { return mode_ == rhs.mode_; }
  bool operator!=(const FpMode& rhs) const { return !(rhs == *this); }

  friend std::ostream& operator<<(std::ostream& os, const FpMode& mode) {
    return os << "(enum: " << mode.EnumVal() << ", raw: 0x" << std::hex
              << mode.RawVal() << std::dec << ")";
  }

  Mode mode() const { return mode_; }

  uint32_t RawVal() const { return EnumToRawVal(mode_); }

  int EnumVal() const { return base::to_underlying(mode_); }
  int MaxEnumVal() const { return base::to_underlying(Mode::kMaxValue); }

 private:
  Mode RawValToEnum(uint32_t mode) const;
  uint32_t EnumToRawVal(Mode mode) const;

  Mode mode_ = Mode::kModeInvalid;
};

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_MODE_H_
