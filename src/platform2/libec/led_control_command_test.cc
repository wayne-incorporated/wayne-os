// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/led_control_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(LedControlCommand, LedControlQueryCommand) {
  LedControlQueryCommand cmd(EC_LED_ID_POWER_LED);
  EXPECT_EQ(cmd.Version(), 1);
  EXPECT_EQ(cmd.Command(), EC_CMD_LED_CONTROL);
  const auto params = cmd.Req();
  EXPECT_EQ(params->led_id, EC_LED_ID_POWER_LED);
  EXPECT_EQ(params->flags, EC_LED_FLAGS_QUERY);
}

class LedControlQueryCommandTest : public testing::Test {
 public:
  class MockLedControlQueryCommand : public LedControlQueryCommand {
   public:
    using LedControlQueryCommand::LedControlQueryCommand;
    MOCK_METHOD(struct ec_response_led_control*, Resp, (), (override));
    MOCK_METHOD(bool, EcCommandRun, (int fd), (override));
  };
};

TEST_F(LedControlQueryCommandTest, Success) {
  MockLedControlQueryCommand mock_command(EC_LED_ID_POWER_LED);
  struct ec_response_led_control response = {
      .brightness_range = {[EC_LED_COLOR_BLUE] = 1, [EC_LED_COLOR_AMBER] = 1}};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));

  EXPECT_TRUE(mock_command.Run(-1));

  const std::array<uint8_t, EC_LED_COLOR_COUNT> brightness_range = {
      {[EC_LED_COLOR_BLUE] = 1, [EC_LED_COLOR_AMBER] = 1}};
  EXPECT_EQ(mock_command.BrightnessRange(), brightness_range);
}

TEST(LedControlCommand, LedControlAutoCommand) {
  LedControlAutoCommand cmd(EC_LED_ID_POWER_LED);
  EXPECT_EQ(cmd.Version(), 1);
  EXPECT_EQ(cmd.Command(), EC_CMD_LED_CONTROL);
  const auto params = cmd.Req();
  EXPECT_EQ(params->led_id, EC_LED_ID_POWER_LED);
  EXPECT_EQ(params->flags, EC_LED_FLAGS_AUTO);
}

TEST(LedControlCommand, LedControlSetCommand) {
  std::array<uint8_t, EC_LED_COLOR_COUNT> brightness = {
      {[EC_LED_COLOR_BLUE] = 1}};
  LedControlSetCommand cmd(EC_LED_ID_POWER_LED, brightness);
  EXPECT_EQ(cmd.Version(), 1);
  EXPECT_EQ(cmd.Command(), EC_CMD_LED_CONTROL);
  const auto params = cmd.Req();
  EXPECT_EQ(params->led_id, EC_LED_ID_POWER_LED);
  EXPECT_EQ(params->flags, 0);
  EXPECT_EQ(params->brightness[EC_LED_COLOR_BLUE], 1);
}

}  // namespace
}  // namespace ec
