// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/get_comms_status_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(GetCommsStatusCommand, GetCommsStatusCommand) {
  GetCommsStatusCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_GET_COMMS_STATUS);
}

// Mock the underlying EcCommand to test.
class GetCommsStatusCommandTest : public testing::Test {
 public:
  class MockGetCommsStatusCommand : public GetCommsStatusCommand {
   public:
    using GetCommsStatusCommand::GetCommsStatusCommand;
    MOCK_METHOD(const struct ec_response_get_comms_status*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(GetCommsStatusCommandTest, IsProcessingTrue) {
  MockGetCommsStatusCommand mock_command;
  struct ec_response_get_comms_status response = {
      .flags = ec_comms_status::EC_COMMS_STATUS_PROCESSING};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(mock_command.IsProcessing());
}

TEST_F(GetCommsStatusCommandTest, IsProcessingFalse) {
  MockGetCommsStatusCommand mock_command;
  struct ec_response_get_comms_status response = {};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_FALSE(mock_command.IsProcessing());
}

}  // namespace
}  // namespace ec
