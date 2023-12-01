// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/fingerprint/fp_stats_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(FpStatsCommand, FpStatsCommand) {
  FpStatsCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_FP_STATS);
}

// Mock the underlying EcCommand to test.
class FpStatsCommandTest : public testing::Test {
 public:
  class MockFpStatsCommand : public FpStatsCommand {
   public:
    using FpStatsCommand::FpStatsCommand;
    MOCK_METHOD(const struct ec_response_fp_stats*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(FpStatsCommandTest, Success) {
  MockFpStatsCommand mock_command;
  struct ec_response_fp_stats response = {.capture_time_us = 1000,
                                          .matching_time_us = 2000,
                                          .overall_time_us = 3000};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.CaptureTime(), base::Microseconds(1000));
  EXPECT_EQ(mock_command.MatchingTime(), base::Microseconds(2000));
  EXPECT_EQ(mock_command.OverallTime(), base::Microseconds(3000));
}

TEST_F(FpStatsCommandTest, InvalidCaptureTimestamp) {
  MockFpStatsCommand mock_command;
  struct ec_response_fp_stats response = {
      .capture_time_us = 1000, .timestamps_invalid = FPSTATS_CAPTURE_INV};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.CaptureTime(), std::nullopt);
}

TEST_F(FpStatsCommandTest, InvalidMatchTimestamp) {
  MockFpStatsCommand mock_command;
  struct ec_response_fp_stats response = {
      .matching_time_us = 1000, .timestamps_invalid = FPSTATS_MATCHING_INV};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.MatchingTime(), std::nullopt);
}

}  // namespace
}  // namespace ec
