// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/fingerprint/fp_mode_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(FpModeCommand, FpModeCommand) {
  FpModeCommand cmd((FpMode(FpMode::Mode::kMatch)));
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_FP_MODE);
  EXPECT_EQ(cmd.Req()->mode, FP_MODE_MATCH);
}

TEST(FpModeCommand, GetFpModeCommand) {
  GetFpModeCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_FP_MODE);
  EXPECT_EQ(cmd.Req()->mode, FP_MODE_DONT_CHANGE);
}

// Mock the underlying EcCommand to test.
class FpModeCommandTest : public testing::Test {
 public:
  class MockFpModeCommand : public FpModeCommand {
   public:
    using FpModeCommand::FpModeCommand;
    MOCK_METHOD(const struct ec_response_fp_mode*, Resp, (), (const, override));
  };
};

class GetFpModeCommandTest : public testing::Test {
 public:
  class MockGetFpModeCommand : public GetFpModeCommand {
   public:
    using GetFpModeCommand::GetFpModeCommand;
    MOCK_METHOD(const struct ec_response_fp_mode*, Resp, (), (const, override));
  };
};

TEST_F(FpModeCommandTest, Success) {
  MockFpModeCommand mock_command((FpMode(FpMode::Mode::kMatch)));
  struct ec_response_fp_mode response = {.mode = FP_MODE_MATCH};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.Mode(), FpMode(FpMode::Mode::kMatch));
}

TEST_F(FpModeCommandTest, InvalidMode) {
  EXPECT_DEATH(FpModeCommand command((FpMode(FpMode::Mode::kModeInvalid))),
               "Check failed: mode != FpMode\\(FpMode::Mode::kModeInvalid\\)");
}

TEST_F(GetFpModeCommandTest, Success) {
  MockGetFpModeCommand mock_command;
  struct ec_response_fp_mode response = {.mode = FP_MODE_CAPTURE};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.Mode(), FpMode(FpMode::Mode::kCapture));
}

}  // namespace
}  // namespace ec
