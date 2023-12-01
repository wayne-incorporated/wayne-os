// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <chromeos/ec/ec_commands.h>

#include "libec/fingerprint/fp_mode.h"

namespace ec {

using Mode = FpMode::Mode;

FpMode::FpMode(uint32_t mode) {
  mode_ = RawValToEnum(mode);
  if (mode_ == Mode::kModeInvalid) {
    LOG(ERROR) << "Attempted to set unrecognized mode: 0x" << std::hex << mode;
  }
}

Mode FpMode::RawValToEnum(uint32_t mode) const {
  switch (mode) {
    case 0:
      return Mode::kNone;
    case FP_MODE_DEEPSLEEP:
      return Mode::kDeepsleep;
    case FP_MODE_FINGER_DOWN:
      return Mode::kFingerDown;
    case FP_MODE_FINGER_UP:
      return Mode::kFingerUp;
    case FP_MODE_CAPTURE:  // Same as Mode::kCaptureVendorFormat.
      return Mode::kCapture;
    case FP_MODE_ENROLL_SESSION:
      return Mode::kEnrollSession;
    case (FP_MODE_ENROLL_SESSION | FP_MODE_FINGER_UP):
      return Mode::kEnrollSessionFingerUp;
    case (FP_MODE_ENROLL_SESSION | FP_MODE_ENROLL_IMAGE):
      return Mode::kEnrollSessionEnrollImage;
    case FP_MODE_ENROLL_IMAGE:
      return Mode::kEnrollImage;
    case FP_MODE_MATCH:
      return Mode::kMatch;
    case FP_MODE_RESET_SENSOR:
      return Mode::kResetSensor;
    case FP_MODE_DONT_CHANGE:
      return Mode::kDontChange;
    case (FP_MODE_CAPTURE | FP_CAPTURE_SIMPLE_IMAGE
                                << FP_MODE_CAPTURE_TYPE_SHIFT):
      return Mode::kCaptureSimpleImage;
    case (FP_MODE_CAPTURE | FP_CAPTURE_PATTERN0 << FP_MODE_CAPTURE_TYPE_SHIFT):
      return Mode::kCapturePattern0;
    case (FP_MODE_CAPTURE | FP_CAPTURE_PATTERN1 << FP_MODE_CAPTURE_TYPE_SHIFT):
      return Mode::kCapturePattern1;
    case (FP_MODE_CAPTURE | FP_CAPTURE_QUALITY_TEST
                                << FP_MODE_CAPTURE_TYPE_SHIFT):
      return Mode::kCaptureQualityTest;
    case (FP_MODE_CAPTURE | FP_CAPTURE_RESET_TEST
                                << FP_MODE_CAPTURE_TYPE_SHIFT):
      return Mode::kCaptureResetTest;
    default:
      return Mode::kModeInvalid;
  }
}

uint32_t FpMode::EnumToRawVal(Mode mode) const {
  switch (mode) {
    case Mode::kModeInvalid:
    case Mode::kNone:
      return 0;
    case Mode::kDeepsleep:
      return FP_MODE_DEEPSLEEP;
    case Mode::kFingerDown:
      return FP_MODE_FINGER_DOWN;
    case Mode::kFingerUp:
      return FP_MODE_FINGER_UP;
    case Mode::kCapture:  // Same as Mode::kCaptureVendorFormat.
      return FP_MODE_CAPTURE;
    case Mode::kEnrollSession:
      return FP_MODE_ENROLL_SESSION;
    case Mode::kEnrollSessionFingerUp:
      return (FP_MODE_ENROLL_SESSION | FP_MODE_FINGER_UP);
    case Mode::kEnrollSessionEnrollImage:
      return (FP_MODE_ENROLL_SESSION | FP_MODE_ENROLL_IMAGE);
    case Mode::kEnrollImage:
      return FP_MODE_ENROLL_IMAGE;
    case Mode::kMatch:
      return FP_MODE_MATCH;
    case Mode::kResetSensor:
      return FP_MODE_RESET_SENSOR;
    case Mode::kDontChange:
      return FP_MODE_DONT_CHANGE;
    case Mode::kSensorMaintenance:
      return FP_MODE_SENSOR_MAINTENANCE;
    case Mode::kCaptureSimpleImage:
      return (FP_MODE_CAPTURE | FP_CAPTURE_SIMPLE_IMAGE
                                    << FP_MODE_CAPTURE_TYPE_SHIFT);
    case Mode::kCapturePattern0:
      return (FP_MODE_CAPTURE | FP_CAPTURE_PATTERN0
                                    << FP_MODE_CAPTURE_TYPE_SHIFT);
    case Mode::kCapturePattern1:
      return (FP_MODE_CAPTURE | FP_CAPTURE_PATTERN1
                                    << FP_MODE_CAPTURE_TYPE_SHIFT);
    case Mode::kCaptureQualityTest:
      return (FP_MODE_CAPTURE | FP_CAPTURE_QUALITY_TEST
                                    << FP_MODE_CAPTURE_TYPE_SHIFT);
    case Mode::kCaptureResetTest:
      return (FP_MODE_CAPTURE | FP_CAPTURE_RESET_TEST
                                    << FP_MODE_CAPTURE_TYPE_SHIFT);
  }
}
}  // namespace ec
