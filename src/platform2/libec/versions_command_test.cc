// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/versions_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(VersionsCommand, VersionsCommand) {
  VersionsCommand cmd(EC_CMD_FP_CONTEXT);
  EXPECT_EQ(cmd.Version(), 1);
  EXPECT_EQ(cmd.Command(), EC_CMD_GET_CMD_VERSIONS);
  EXPECT_EQ(cmd.CommandCode(), EC_CMD_FP_CONTEXT);
}

// Mock the underlying EcCommand to test
class VersionsCommandTest : public testing::Test {
 public:
  class MockVersionsCommand : public VersionsCommand {
   public:
    using VersionsCommand::VersionsCommand;
    MOCK_METHOD(bool, Run, (int fd), (override));
    MOCK_METHOD(struct ec_response_get_cmd_versions*, Resp, (), (override));
    MOCK_METHOD(uint32_t, Result, (), (const, override));
  };
};

TEST_F(VersionsCommandTest, Unknown) {
  VersionsCommand cmd(EC_CMD_FP_CONTEXT);
  // The command has not been run, so we don't know the status.
  EXPECT_EQ(cmd.IsVersionSupported(1), EcCmdVersionSupportStatus::UNKNOWN);
}

TEST_F(VersionsCommandTest, CommandNotFound) {
  MockVersionsCommand mock_command(EC_CMD_FP_CONTEXT);
  EXPECT_CALL(mock_command, Result)
      .WillRepeatedly(Return(EC_RES_INVALID_COMMAND));

  EXPECT_EQ(mock_command.IsVersionSupported(1),
            EcCmdVersionSupportStatus::UNSUPPORTED);
}

TEST_F(VersionsCommandTest, CommandNotSupported) {
  MockVersionsCommand mock_command(EC_CMD_FP_CONTEXT);
  EXPECT_CALL(mock_command, Result).WillRepeatedly(Return(EC_RES_SUCCESS));
  constexpr int kVersionZero = 0;
  constexpr int kVersionOne = 1;
  struct ec_response_get_cmd_versions response = {.version_mask =
                                                      1 << kVersionZero};
  EXPECT_CALL(mock_command, Resp).WillOnce(Return(&response));

  EXPECT_EQ(mock_command.IsVersionSupported(kVersionOne),
            EcCmdVersionSupportStatus::UNSUPPORTED);
}

TEST_F(VersionsCommandTest, CommandSupported) {
  MockVersionsCommand mock_command(EC_CMD_FP_CONTEXT);
  EXPECT_CALL(mock_command, Result).WillRepeatedly(Return(EC_RES_SUCCESS));
  constexpr int kVersionOne = 1;
  struct ec_response_get_cmd_versions response = {.version_mask =
                                                      1 << kVersionOne};
  EXPECT_CALL(mock_command, Resp).WillOnce(Return(&response));

  EXPECT_EQ(mock_command.IsVersionSupported(kVersionOne),
            EcCmdVersionSupportStatus::SUPPORTED);
}

TEST_F(VersionsCommandTest, InvalidParamShouldNotBeRetried) {
  MockVersionsCommand mock_command(EC_CMD_FP_CONTEXT);

  // We should only run the command once even though we specify retries,
  // since this type of failure cannot be retried.
  EXPECT_CALL(mock_command, Run).WillOnce(Return(false));
  EXPECT_CALL(mock_command, Result).WillOnce(Return(EC_RES_INVALID_PARAM));

  constexpr int kTestFd = -1;
  constexpr int kNumAttempts = 2;
  EXPECT_FALSE(mock_command.RunWithMultipleAttempts(kTestFd, kNumAttempts));
}

}  // namespace
}  // namespace ec
