// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/test_util.h"

#include <gtest/gtest.h>

namespace croslog {

base::Time TimeFromExploded(int year,
                            int month,
                            int day_of_month,
                            int hour,
                            int minute,
                            int second,
                            int micro_second,
                            int timezone_offset_hour) {
  base::Time time;
  EXPECT_TRUE(base::Time::FromUTCExploded(
      base::Time::Exploded{year, month, 0, day_of_month, hour, minute, second,
                           0},
      &time));
  time += base::Microseconds(micro_second);
  time -= base::Hours(timezone_offset_hour);
  return time;
}

}  // namespace croslog
