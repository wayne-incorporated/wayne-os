// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/get_protocol_info_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(GetProtocolInfoCommand, GetProtocolInfoCommand) {
  GetProtocolInfoCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_GET_PROTOCOL_INFO);
}

// Mock the underlying EcCommand to test.
class GetProtocolInfoCommandTest : public testing::Test {
 public:
  class MockGetProtocolInfoCommand : public GetProtocolInfoCommand {
   public:
    using GetProtocolInfoCommand::GetProtocolInfoCommand;
    MOCK_METHOD(struct ec_response_get_protocol_info*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(GetProtocolInfoCommandTest, Success) {
  MockGetProtocolInfoCommand mock_command;
  struct ec_response_get_protocol_info response = {
      .max_request_packet_size = 544, .max_response_packet_size = 544};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.MaxReadBytes(), 536);
  EXPECT_EQ(mock_command.MaxWriteBytes(), 532);
}

}  // namespace
}  // namespace ec
