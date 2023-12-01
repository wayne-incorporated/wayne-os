// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/display_soc_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(DisplayStateOfChargeCommand, DisplayStateOfChargeCommand) {
  DisplayStateOfChargeCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_DISPLAY_SOC);
}

// Mock the underlying EcCommand to test.
class DisplayStateOfChargeCommandTest : public testing::Test {
 public:
  class MockDisplayStateOfChargeCommand : public DisplayStateOfChargeCommand {
   public:
    using DisplayStateOfChargeCommand::DisplayStateOfChargeCommand;
    MOCK_METHOD(struct ec_response_display_soc*, Resp, (), (const, override));
  };
};

TEST_F(DisplayStateOfChargeCommandTest, Success) {
  MockDisplayStateOfChargeCommand mock_command;
  struct ec_response_display_soc response = {
      .display_soc = 990, .full_factor = 1000, .shutdown_soc = 10};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.CurrentPercentCharge(), 99.0);
  EXPECT_EQ(mock_command.FullFactor(), 1.0);
  EXPECT_EQ(mock_command.ShutdownPercentCharge(), 1.0);
}

}  // namespace
}  // namespace ec
