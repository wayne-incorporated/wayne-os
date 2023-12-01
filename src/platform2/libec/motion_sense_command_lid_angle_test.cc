// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/motion_sense_command_lid_angle.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(MotionSenseCommandLidAngle, MotionSenseCommandLidAngle) {
  MotionSenseCommandLidAngle cmd;
  EXPECT_EQ(cmd.Version(), 2);
  EXPECT_EQ(cmd.Command(), EC_CMD_MOTION_SENSE_CMD);
  EXPECT_EQ(cmd.Req()->cmd, MOTIONSENSE_CMD_LID_ANGLE);
  EXPECT_EQ(cmd.ReqSize(), sizeof(ec_params_motion_sense::cmd));
  EXPECT_EQ(cmd.RespSize(), sizeof(ec_response_motion_sense::lid_angle));
}

// Mock the underlying EcCommand to test.
class MotionSenseCommandLidAngleTest : public testing::Test {
 public:
  class MockGetLidAngleCommand : public MotionSenseCommandLidAngle {
   public:
    using MotionSenseCommandLidAngle::MotionSenseCommandLidAngle;
    MOCK_METHOD(struct ec_response_motion_sense*, Resp, (), (const override));
  };
};

TEST_F(MotionSenseCommandLidAngleTest, Success) {
  MockGetLidAngleCommand mock_command;
  struct ec_response_motion_sense response = {.lid_angle = {.value = 120}};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_EQ(mock_command.LidAngle(), 120);
}

}  // namespace
}  // namespace ec
