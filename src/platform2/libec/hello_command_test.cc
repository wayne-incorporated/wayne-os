// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/hello_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(HelloCommand, HelloCommand) {
  HelloCommand cmd(42);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_HELLO);
  EXPECT_EQ(cmd.Req()->in_data, 42);
}

// Mock the underlying EcCommand to test.
class HelloCommandTest : public testing::Test {
 public:
  class MockHelloCommand : public HelloCommand {
   public:
    using HelloCommand::HelloCommand;
    MOCK_METHOD(const struct ec_response_hello*, Resp, (), (const, override));
  };
};

TEST_F(HelloCommandTest, IsFeatureSupported) {
  MockHelloCommand mock_command(1);
  struct ec_response_hello response {
    .out_data = 1 + 0x01020304
  };

  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.GetResponseData(), 0x01020305);
}

}  // namespace
}  // namespace ec
