// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/battery_percentage_converter.h"

#include <cmath>

#include <gtest/gtest.h>

namespace power_manager {

namespace {

constexpr double kLowBatteryShutdownPercent = 4.0;
constexpr double kFullFactor = 0.97;

class BatteryPercentageConverterTest : public ::testing::Test {
 public:
  BatteryPercentageConverterTest() = default;
  BatteryPercentageConverterTest(const BatteryPercentageConverterTest&) =
      delete;
  BatteryPercentageConverterTest& operator=(
      const BatteryPercentageConverterTest&) = delete;

 protected:
  BatteryPercentageConverter converter_{kLowBatteryShutdownPercent,
                                        kFullFactor};
};

}  // namespace

// Tests that |ConvertActualToDisplay| is the partially inverse function of
// |ConvertDisplayToActual|.
TEST_F(BatteryPercentageConverterTest,
       ConvertActualToDisplayIsPartiallyInverse) {
  constexpr double kActual = 86.0;
  constexpr double kExpectedDisplay =
      100.0 * (kActual - kLowBatteryShutdownPercent) /
      (100 * kFullFactor - kLowBatteryShutdownPercent);

  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(kActual),
                   kExpectedDisplay);
  EXPECT_DOUBLE_EQ(converter_.ConvertDisplayToActual(kExpectedDisplay),
                   kActual);
}

// Tests that |ConvertActualToDisplay| is the not inverse function of
// |ConvertDisplayToActual|.
TEST_F(BatteryPercentageConverterTest, ConvertActualToDisplayIsNotInverse) {
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(0.0), 0.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(1.0), 0.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(2.0), 0.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(3.0), 0.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(4.0), 0.0);

  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(97.0), 100.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(98.0), 100.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(99.0), 100.0);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(100.0), 100.0);
}

// Tests that |ConvertDisplayToActual| is the inverse function of
// |ConvertActualToDisplay|.
TEST_F(BatteryPercentageConverterTest, ConvertDisplayToActualIsInverse) {
  constexpr double kDisplay = 88.0;
  constexpr double kExpectedActual =
      kFullFactor * kDisplay + kLowBatteryShutdownPercent -
      kDisplay * kLowBatteryShutdownPercent / 100.0;

  EXPECT_DOUBLE_EQ(converter_.ConvertDisplayToActual(kDisplay),
                   kExpectedActual);
  EXPECT_DOUBLE_EQ(converter_.ConvertActualToDisplay(kExpectedActual),
                   kDisplay);
}

}  // namespace power_manager
