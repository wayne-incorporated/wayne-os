// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "timberslide/string_transformer.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

namespace timberslide {
namespace {

struct TestExample {
  std::vector<std::string> input;
  int64_t ec_uptime;
  base::Time::Exploded timestamp;
  std::vector<std::string> expected_result;
};

TestExample kTransformerTestData[]{
    {{"[1.362299 Sensor create: 0x0]", "[1.898121 HC 0x0b]",
      "[1.898910 HC 0x400b]", "[1.898964 HC 0x400b err 1]",
      "[1.899776 HC 0x08]", "+[1.900544 HC 0x08 err 3]", "[1.901188 HC 0x8d]",
      "[1.901239 HC 0x8d err 1]"},
     8204,
     {.year = 2021,
      .month = 8,
      .day_of_week = 5,
      .day_of_month = 20,
      .hour = 7,
      .minute = 56,
      .second = 27,
      .millisecond = 285},
     {"2021-08-20T07:56:20.443000Z [1.362299 Sensor create: 0x0]",
      "2021-08-20T07:56:20.979000Z [1.898121 HC 0x0b]",
      "2021-08-20T07:56:20.979000Z [1.898910 HC 0x400b]",
      "2021-08-20T07:56:20.979000Z [1.898964 HC 0x400b err 1]",
      "2021-08-20T07:56:20.980000Z [1.899776 HC 0x08]",
      "2021-08-20T07:56:20.981000Z +[1.900544 HC 0x08 err 3]",
      "2021-08-20T07:56:20.982000Z [1.901188 HC 0x8d]",
      "2021-08-20T07:56:20.982000Z [1.901239 HC 0x8d err 1]"}},
    {{"[2.947845 HC 0x408]", "+[2.948953 Seed has already been set.]",
      "[2.948997 HC 0x408 err 4]", "[8.151214 HC 0x02]", "[8.152845 HC 0x0b]"},
     12202,
     {.year = 2021,
      .month = 8,
      .day_of_week = 5,
      .day_of_month = 20,
      .hour = 7,
      .minute = 56,
      .second = 31,
      .millisecond = 263},
     {"2021-08-20T07:56:22.008000Z [2.947845 HC 0x408]",
      "2021-08-20T07:56:22.009000Z +[2.948953 Seed has already been set.]",
      "2021-08-20T07:56:22.009000Z [2.948997 HC 0x408 err 4]",
      "2021-08-20T07:56:27.212000Z [8.151214 HC 0x02]",
      "2021-08-20T07:56:27.213000Z [8.152845 HC 0x0b]"}},
    {{"Console is enabled; type HELP for help.",
      "> [1.124173 event set 0x0000000000002000]",
      "[1.124243 hostcmd init 0x0000000000002000]"},
     8204,
     {.year = 2021,
      .month = 8,
      .day_of_week = 5,
      .day_of_month = 20,
      .hour = 7,
      .minute = 56,
      .second = 27,
      .millisecond = 285},
     {"1970-01-01T00:00:00.000000Z Console is enabled; type HELP for help.",
      "2021-08-20T07:56:20.205000Z > [1.124173 event set 0x0000000000002000]",
      "2021-08-20T07:56:20.205000Z [1.124243 hostcmd init "
      "0x0000000000002000]"}},
    {{"[1.124305 FP_SENSOR_SEL: FPC]", "FPC libfpsensor.a v0.2.0.064",
      "[1.191592 FPC1145 id 0x140c]"},
     8204,
     {.year = 2021,
      .month = 8,
      .day_of_week = 5,
      .day_of_month = 20,
      .hour = 7,
      .minute = 56,
      .second = 27,
      .millisecond = 285},
     {"2021-08-20T07:56:20.205000Z [1.124305 FP_SENSOR_SEL: FPC]",
      "2021-08-20T07:56:20.205000Z FPC libfpsensor.a v0.2.0.064",
      "2021-08-20T07:56:20.272000Z [1.191592 FPC1145 id 0x140c]"}},
    {.input = {"[1.124305 FP_SENSOR_SEL: FPC]", "FPC libfpsensor.a v0.2.0.064",
               "[1.191592 FPC1145 id 0x140c]"},
     .expected_result =
         {"1970-01-01T00:00:00.000000Z [1.124305 FP_SENSOR_SEL: FPC]",
          "1970-01-01T00:00:00.000000Z FPC libfpsensor.a v0.2.0.064",
          "1970-01-01T00:00:00.000000Z [1.191592 FPC1145 id 0x140c]"}},
};

void CheckStringTransform(StringTransformer* xfrm,
                          const TestExample& example,
                          bool update_timestamp) {
  base::Time timestamp;

  if (update_timestamp) {
    ASSERT_TRUE(base::Time::FromUTCExploded(example.timestamp, &timestamp));
    xfrm->UpdateTimestamps(example.ec_uptime, timestamp);
  }

  for (int i = 0; i < example.input.size(); i++)
    EXPECT_EQ(xfrm->AddHostTs(example.input[i]), example.expected_result[i]);
}

// Check basic functionality
TEST(StringTransformerTest, TestAddTimestamp) {
  StringTransformer xfrm;
  CheckStringTransform(&xfrm, kTransformerTestData[0], true);
  CheckStringTransform(&xfrm, kTransformerTestData[1], true);
}

// Check if first lines without EC timestamp in first block have timestamp
// equal to 0101/000000.000000, but when previous timestamp is available then
// it is applied to line without EC timestamp
TEST(StringTransformerTest, TestLinesWithoutTimestamp) {
  StringTransformer xfrm;
  CheckStringTransform(&xfrm, kTransformerTestData[2], true);
  CheckStringTransform(&xfrm, kTransformerTestData[3], true);
}

// Check if 0101/000000.000000 is applied to all lines in block when
// timestamps are not initialized
TEST(StringTransformerTest, TestTimestampsNotInitialized) {
  StringTransformer xfrm;
  CheckStringTransform(&xfrm, kTransformerTestData[4], false);
}

}  // namespace
}  // namespace timberslide
