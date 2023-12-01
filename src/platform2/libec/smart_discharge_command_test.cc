// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/smart_discharge_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(SmartDischargeCommand, SmartDischargeCommand) {
  SmartDischargeCommand cmd;
  EXPECT_EQ(cmd.Command(), EC_CMD_SMART_DISCHARGE);
  EXPECT_EQ(cmd.Req()->flags, 0);
}

TEST(SmartDischargeCommand, SmartDischargeCommandSet) {
  // Constructor for setting values.
  SmartDischargeCommand cmd(1, 2, 3);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_SMART_DISCHARGE);
  EXPECT_EQ(cmd.Req()->flags, EC_SMART_DISCHARGE_FLAGS_SET);
  EXPECT_EQ(cmd.Req()->hours_to_zero, 1);
  EXPECT_EQ(cmd.Req()->drate.cutoff, 2);
  EXPECT_EQ(cmd.Req()->drate.hibern, 3);
}

// Mock the underlying EcCommand to test.
class SmartDischargeCommandTest : public testing::Test {
 public:
  class MockSmartDischargeCommand : public SmartDischargeCommand {
   public:
    using SmartDischargeCommand::SmartDischargeCommand;
    MOCK_METHOD(const struct ec_response_smart_discharge*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(SmartDischargeCommandTest, Success) {
  MockSmartDischargeCommand mock_command;
  struct ec_response_smart_discharge response = {
      .hours_to_zero = 1,
      .drate = {.cutoff = 2, .hibern = 3},
      .dzone = {.cutoff = 4, .stayup = 5}};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.HoursToZero(), 1);
  EXPECT_EQ(mock_command.CutoffCurrentMicroAmps(), 2);
  EXPECT_EQ(mock_command.HibernationCurrentMicroAmps(), 3);
  EXPECT_EQ(mock_command.BatteryCutoffThresholdMilliAmpHours(), 4);
  EXPECT_EQ(mock_command.ECStayupThresholdMilliAmpHours(), 5);
}

}  // namespace
}  // namespace ec
