// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/ec_command.h"
#include "libec/rgb_keyboard_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(RgbkbdSetColorCommand, HeaderSize) {
  EXPECT_EQ(sizeof(rgb_keyboard::Header), sizeof(ec_params_rgbkbd_set_color));
}

TEST(RgbkbdSetColorCommand, RgbkbdSetColorCommandSingle) {
  const std::vector<struct rgb_s> expected = {
      {.r = 0xaa, .g = 0xbb, .b = 0xcc},
  };
  uint8_t start_key = 0xdd;

  RgbkbdSetColorCommand cmd(start_key, expected);
  EXPECT_EQ(cmd.Command(), EC_CMD_RGBKBD_SET_COLOR);
  EXPECT_GE(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->req.start_key, start_key);
  EXPECT_EQ(cmd.Req()->req.length, expected.size());
  EXPECT_EQ(cmd.Req()->color[0].r, expected[0].r);
  EXPECT_EQ(cmd.Req()->color[0].g, expected[0].g);
  EXPECT_EQ(cmd.Req()->color[0].b, expected[0].b);
}

TEST(RgbkbdSetColorCommand, RgbkbdSetColorCommandMultiple) {
  std::vector<struct rgb_s> color;
  std::array<struct rgb_s, 128> expected;
  uint8_t start_key = 0;

  for (int i = 0; i < expected.size(); i++) {
    expected[i].r = std::rand() & 0xff;
    expected[i].g = std::rand() & 0xff;
    expected[i].b = std::rand() & 0xff;
  }
  std::copy(expected.begin(), expected.end(), std::back_inserter(color));
  RgbkbdSetColorCommand cmd(start_key, color);
  EXPECT_EQ(cmd.Command(), EC_CMD_RGBKBD_SET_COLOR);
  EXPECT_GE(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->req.start_key, start_key);
  EXPECT_EQ(cmd.Req()->req.length, expected.size());
  EXPECT_EQ(std::memcmp(&cmd.Req()->color[0], &expected[0],
                        expected.size() * sizeof(expected[0])),
            0);
}

TEST(RgbkbdCommand, RgbkbdClearCommand) {
  struct rgb_s color;

  color.r = 0x0a;
  color.g = 0x0b;
  color.b = 0x0c;

  auto cmd = RgbkbdCommand::Create(EC_RGBKBD_SUBCMD_CLEAR, color);
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Command(), EC_CMD_RGBKBD);
  EXPECT_EQ(cmd->Version(), 0);
  EXPECT_EQ(cmd->Req()->subcmd, EC_RGBKBD_SUBCMD_CLEAR);
  EXPECT_EQ(cmd->Req()->color.r, color.r);
  EXPECT_EQ(cmd->Req()->color.g, color.g);
  EXPECT_EQ(cmd->Req()->color.b, color.b);

  cmd = RgbkbdCommand::Create(EC_RGBKBD_SUBCMD_COUNT, color);
  EXPECT_FALSE(cmd);
}

TEST(RgbkbdCommand, RgbkbdGetConfigCommand) {
  auto cmd = RgbkbdCommand::Create(EC_RGBKBD_SUBCMD_GET_CONFIG);
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Command(), EC_CMD_RGBKBD);
  EXPECT_EQ(cmd->Version(), 0);
  EXPECT_EQ(cmd->Req()->subcmd, EC_RGBKBD_SUBCMD_GET_CONFIG);
}

// Mock the underlying EcCommand to test.
class RgbkbdCommandTest : public testing::Test {
 public:
  class MockRgbkbdCommand : public RgbkbdCommand {
   public:
    using RgbkbdCommand::RgbkbdCommand;
    MOCK_METHOD(struct ec_response_rgbkbd*, Resp, (), (const, override));
  };
};

TEST_F(RgbkbdCommandTest, RgbkbdGetConfigResponse) {
  auto mock_cmd =
      RgbkbdCommand::Create<MockRgbkbdCommand>(EC_RGBKBD_SUBCMD_GET_CONFIG);

  struct ec_response_rgbkbd response = {.rgbkbd_type = 2};

  EXPECT_CALL(*mock_cmd, Resp).WillRepeatedly(Return(&response));
  EXPECT_EQ(mock_cmd->GetConfig(), 2);
}

}  // namespace
}  // namespace ec
