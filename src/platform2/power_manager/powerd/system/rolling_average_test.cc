// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/rolling_average.h"

#include <stdint.h>

#include <gtest/gtest.h>

namespace power_manager::system {

TEST(RollingAverageTest, SingleSample) {
  RollingAverage average(1);
  average.AddSample(5.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(5.0, average.GetAverage());
  average.AddSample(0.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(0.0, average.GetAverage());
  average.AddSample(4.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(4.0, average.GetAverage());
  average.AddSample(-1.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(-1.0, average.GetAverage());
}

TEST(RollingAverageTest, MultipleSamples) {
  RollingAverage average(3);
  average.AddSample(4.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(4.0, average.GetAverage());
  average.AddSample(8.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(6.0, average.GetAverage());
  average.AddSample(12.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(8.0, average.GetAverage());
  average.AddSample(10.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(10.0, average.GetAverage());
  average.AddSample(-4.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(6.0, average.GetAverage());
}

TEST(RollingAverageTest, GetDelta) {
  const base::TimeTicks kTime1 = base::TimeTicks() + base::Microseconds(1000);
  const base::TimeTicks kTime2 = base::TimeTicks() + base::Microseconds(2000);
  const base::TimeTicks kTime3 = base::TimeTicks() + base::Microseconds(4000);
  const base::TimeTicks kTime4 = base::TimeTicks() + base::Microseconds(8000);

  const double kValue1 = 10.0;
  const double kValue2 = 4.0;
  const double kValue3 = -5.0;
  const double kValue4 = 13.0;

  RollingAverage average(3);
  EXPECT_EQ(base::TimeDelta(), average.GetTimeDelta());
  EXPECT_EQ(0.0, average.GetValueDelta());

  average.AddSample(kValue1, kTime1);
  EXPECT_EQ(base::TimeDelta(), average.GetTimeDelta());
  EXPECT_EQ(0.0, average.GetValueDelta());

  average.AddSample(kValue2, kTime2);
  EXPECT_EQ((kTime2 - kTime1), average.GetTimeDelta());
  EXPECT_EQ(kValue2 - kValue1, average.GetValueDelta());

  average.AddSample(kValue3, kTime3);
  EXPECT_EQ((kTime3 - kTime1), average.GetTimeDelta());
  EXPECT_EQ(kValue3 - kValue1, average.GetValueDelta());

  average.AddSample(kValue4, kTime4);
  EXPECT_EQ((kTime4 - kTime2), average.GetTimeDelta());
  EXPECT_EQ(kValue4 - kValue2, average.GetValueDelta());
}

TEST(RollingAverageTest, Clear) {
  RollingAverage average(2);
  average.AddSample(3.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(3.0, average.GetAverage());
  average.AddSample(2.0, base::TimeTicks());
  EXPECT_DOUBLE_EQ(2.5, average.GetAverage());
  average.Clear();
  EXPECT_DOUBLE_EQ(0.0, average.GetAverage());
}

TEST(RollingAverageTest, HasMaxSamples) {
  RollingAverage average(3);
  average.AddSample(1.0, base::TimeTicks());
  EXPECT_EQ(false, average.HasMaxSamples());
  average.AddSample(2.0, base::TimeTicks());
  EXPECT_EQ(false, average.HasMaxSamples());
  average.AddSample(3.0, base::TimeTicks());
  EXPECT_EQ(true, average.HasMaxSamples());
  average.AddSample(4.0, base::TimeTicks());
  EXPECT_EQ(true, average.HasMaxSamples());
  average.Clear();
  EXPECT_EQ(false, average.HasMaxSamples());
  average.AddSample(1.0, base::TimeTicks());
  EXPECT_EQ(false, average.HasMaxSamples());
  average.AddSample(2.0, base::TimeTicks());
  EXPECT_EQ(false, average.HasMaxSamples());
}

}  // namespace power_manager::system
