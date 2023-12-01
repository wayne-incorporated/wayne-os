// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <gtest/gtest.h>

#include "libec/fingerprint/fp_mode.h"

namespace ec {

using Mode = FpMode::Mode;

TEST(FpModeTest, Constructor) {
  EXPECT_EQ(FpMode().mode(), Mode::kModeInvalid);
  EXPECT_EQ(FpMode(Mode::kResetSensor).mode(), Mode::kResetSensor);
  EXPECT_EQ(FpMode(1).mode(), Mode::kDeepsleep);
  EXPECT_EQ(FpMode(UINT32_MAX).mode(), Mode::kModeInvalid);
}

TEST(FpModeTest, Equality) {
  EXPECT_EQ(FpMode(Mode::kResetSensor), FpMode(Mode::kResetSensor));
  EXPECT_NE(FpMode(Mode::kResetSensor), FpMode(Mode::kMatch));
}

TEST(FpModeTest, Ostream) {
  std::ostringstream stream;
  stream << "mode: " << FpMode(Mode::kResetSensor);
  EXPECT_EQ(stream.str(), "mode: (enum: 10, raw: 0x80)");
}

TEST(FpModeTest, EnumVal) {
  EXPECT_EQ(FpMode(Mode::kNone).EnumVal(), 0);
  EXPECT_EQ(FpMode(Mode::kDeepsleep).EnumVal(), 1);
  EXPECT_EQ(FpMode(Mode::kFingerDown).EnumVal(), 2);
  EXPECT_EQ(FpMode(Mode::kFingerUp).EnumVal(), 3);
  EXPECT_EQ(FpMode(Mode::kCapture).EnumVal(), 4);
  EXPECT_EQ(FpMode(Mode::kEnrollSession).EnumVal(), 5);
  EXPECT_EQ(FpMode(Mode::kEnrollSessionFingerUp).EnumVal(), 6);
  EXPECT_EQ(FpMode(Mode::kEnrollSessionEnrollImage).EnumVal(), 7);
  EXPECT_EQ(FpMode(Mode::kEnrollImage).EnumVal(), 8);
  EXPECT_EQ(FpMode(Mode::kMatch).EnumVal(), 9);
  EXPECT_EQ(FpMode(Mode::kResetSensor).EnumVal(), 10);
  EXPECT_EQ(FpMode(Mode::kDontChange).EnumVal(), 11);
  EXPECT_EQ(FpMode(Mode::kSensorMaintenance).EnumVal(), 12);
  EXPECT_EQ(FpMode(Mode::kModeInvalid).EnumVal(), 13);
  EXPECT_EQ(FpMode(Mode::kCaptureVendorFormat).EnumVal(),
            FpMode(Mode::kCapture).EnumVal());
  EXPECT_EQ(FpMode(Mode::kCaptureSimpleImage).EnumVal(), 14);
  EXPECT_EQ(FpMode(Mode::kCapturePattern0).EnumVal(), 15);
  EXPECT_EQ(FpMode(Mode::kCapturePattern1).EnumVal(), 16);
  EXPECT_EQ(FpMode(Mode::kCaptureQualityTest).EnumVal(), 17);
  EXPECT_EQ(FpMode(Mode::kCaptureResetTest).EnumVal(), 18);
}

TEST(FpModeTest, MaxEnumVal) {
  EXPECT_EQ(FpMode().MaxEnumVal(), 18);
}

TEST(FpModeTest, RawVal) {
  EXPECT_EQ(FpMode(Mode::kNone).RawVal(), 0);
  EXPECT_EQ(FpMode(Mode::kModeInvalid).RawVal(), 0);

  EXPECT_EQ(FpMode(Mode::kDeepsleep).RawVal(), 0x1);
  EXPECT_EQ(FpMode(Mode::kFingerDown).RawVal(), 0x2);
  EXPECT_EQ(FpMode(Mode::kFingerUp).RawVal(), 0x4);
  EXPECT_EQ(FpMode(Mode::kCapture).RawVal(), 0x8);
  EXPECT_EQ(FpMode(Mode::kEnrollSession).RawVal(), 0x10);
  EXPECT_EQ(FpMode(Mode::kEnrollImage).RawVal(), 0x20);
  EXPECT_EQ(FpMode(Mode::kMatch).RawVal(), 0x40);
  EXPECT_EQ(FpMode(Mode::kResetSensor).RawVal(), 0x80);
  EXPECT_EQ(FpMode(Mode::kSensorMaintenance).RawVal(), 0x100);
  EXPECT_EQ(FpMode(Mode::kDontChange).RawVal(), 0x80000000);

  EXPECT_EQ(FpMode(Mode::kEnrollSessionFingerUp).RawVal(), 0x14);
  EXPECT_EQ(FpMode(Mode::kEnrollSessionEnrollImage).RawVal(), 0x30);

  EXPECT_EQ(FpMode(Mode::kCaptureVendorFormat).RawVal(),
            FpMode(Mode::kCapture).RawVal());
  EXPECT_EQ(FpMode(Mode::kCaptureSimpleImage).RawVal(), 0x10000008);
  EXPECT_EQ(FpMode(Mode::kCapturePattern0).RawVal(), 0x20000008);
  EXPECT_EQ(FpMode(Mode::kCapturePattern1).RawVal(), 0x30000008);
  EXPECT_EQ(FpMode(Mode::kCaptureQualityTest).RawVal(), 0x40000008);
  EXPECT_EQ(FpMode(Mode::kCaptureResetTest).RawVal(), 0x50000008);
}

}  // namespace ec
