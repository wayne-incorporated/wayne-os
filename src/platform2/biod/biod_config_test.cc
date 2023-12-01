// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_config.h"

#include <cros_config/fake_cros_config.h>
#include <gtest/gtest.h>

namespace biod {

TEST(FingerprintSupportedTest, FingerprintLocationUnset) {
  // Given a device that does not indicate fingerprint sensor location
  brillo::FakeCrosConfig cros_config;
  // expect FingerprintSupported to report false.
  EXPECT_FALSE(FingerprintSupported(&cros_config));
}

TEST(FingerprintSupportedTest, FingerprintLocationSet) {
  brillo::FakeCrosConfig cros_config;
  cros_config.SetString(kCrosConfigFPPath, kCrosConfigFPLocation,
                        "power-button-top-left");
  EXPECT_TRUE(FingerprintSupported(&cros_config));
}

TEST(FingerprintSupportedTest, FingerprintLocationSetNone) {
  brillo::FakeCrosConfig cros_config;
  cros_config.SetString(kCrosConfigFPPath, kCrosConfigFPLocation, "none");
  EXPECT_FALSE(FingerprintSupported(&cros_config));
}

TEST(FingerprintBoardTest, FingerprintBoardUnset) {
  // Given a device that does not indicate fingerprint board
  brillo::FakeCrosConfig cros_config;
  // expect FingerprintBoard to report false.
  EXPECT_FALSE(FingerprintBoard(&cros_config));
}

TEST(FingerprintBoardTest, FingerprintBoardSet) {
  brillo::FakeCrosConfig cros_config;
  cros_config.SetString(kCrosConfigFPPath, kCrosConfigFPBoard,
                        kFpBoardDartmonkey);
  EXPECT_EQ(FingerprintBoard(&cros_config), kFpBoardDartmonkey);
}

}  // namespace biod
