// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/pwm_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(SetKeyboardBacklightCommand, SetKeyboardBacklightCommand) {
  uint8_t percent = 50;

  SetKeyboardBacklightCommand cmd(percent);
  EXPECT_EQ(cmd.Command(), EC_CMD_PWM_SET_KEYBOARD_BACKLIGHT);
  EXPECT_GE(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->percent, percent);
}

// Mock the underlying EcCommand to test.
class GetKeyboardBacklightCommandTest : public testing::Test {
 public:
  class MockGetKeyboardBacklightCommand : public GetKeyboardBacklightCommand {
   public:
    using GetKeyboardBacklightCommand::GetKeyboardBacklightCommand;
    MOCK_METHOD(struct ec_response_pwm_get_keyboard_backlight*,
                Resp,
                (),
                (const, override));
  };
};

TEST(GetKeyboardBacklightCommand, GetKeyboardBacklightCommand) {
  GetKeyboardBacklightCommand cmd;
  EXPECT_EQ(cmd.Command(), EC_CMD_PWM_GET_KEYBOARD_BACKLIGHT);
  EXPECT_GE(cmd.Version(), 0);
}

TEST_F(GetKeyboardBacklightCommandTest, Success) {
  MockGetKeyboardBacklightCommand mock_command;
  struct ec_response_pwm_get_keyboard_backlight response = {.percent = 50};

  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_EQ(mock_command.Brightness(), 50);
}

}  // namespace
}  // namespace ec
