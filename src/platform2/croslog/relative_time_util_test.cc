// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/relative_time_util.h"

#include <memory>
#include <string>
#include <utility>

#include "gtest/gtest.h"

#include "croslog/test_util.h"

namespace croslog {

class RelativeTimeUtilTest : public ::testing::Test {
 public:
  RelativeTimeUtilTest() = default;
  RelativeTimeUtilTest(const RelativeTimeUtilTest&) = delete;
  RelativeTimeUtilTest& operator=(const RelativeTimeUtilTest&) = delete;
};

TEST_F(RelativeTimeUtilTest, Parse) {
  const auto tol = base::Milliseconds(100);
  base::Time output;
  base::Time target_time;

  EXPECT_TRUE(ParseRelativeTime("-100", &output));
  // The return value of base::Time::Now() here is slightly different from that
  // in ParseRelativeTime(), allow an error of no more than tol
  target_time = base::Time::Now() - base::Seconds(100);
  EXPECT_LE(target_time - tol, output);
  EXPECT_GE(target_time, output);

  EXPECT_TRUE(ParseRelativeTime("+600", &output));
  target_time = base::Time::Now() + base::Seconds(600);
  EXPECT_LE(target_time - tol, output);
  EXPECT_GE(target_time, output);

  EXPECT_TRUE(ParseRelativeTime("-0", &output));
  target_time = base::Time::Now();
  EXPECT_LE(target_time - tol, output);
  EXPECT_GE(target_time, output);
}

TEST_F(RelativeTimeUtilTest, ParseInvalid) {
  base::Time output;
  EXPECT_FALSE(ParseRelativeTime("60", &output));
  EXPECT_FALSE(ParseRelativeTime("+1second", &output));
  EXPECT_FALSE(ParseRelativeTime("", &output));
  EXPECT_FALSE(ParseRelativeTime(" -60", &output));
}

}  // namespace croslog
