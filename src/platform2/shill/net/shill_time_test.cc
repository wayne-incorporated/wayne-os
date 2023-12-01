// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/shill_time.h"

#include <time.h>

#include <gtest/gtest.h>

using testing::Test;

namespace shill {

class TimeTest : public Test {};

TEST_F(TimeTest, FormatTime) {
  const time_t kEpochStart = 0;
  const char kEpochStartString[] = "1970-01-01T00:00:00.000000+0000";
  struct tm epoch_start_tm;
  gmtime_r(&kEpochStart, &epoch_start_tm);
  EXPECT_EQ(kEpochStartString, Time::FormatTime(epoch_start_tm, 0));
}

}  // namespace shill
