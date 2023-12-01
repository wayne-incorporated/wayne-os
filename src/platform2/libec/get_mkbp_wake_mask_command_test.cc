// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/get_mkbp_wake_mask_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(GetMkbpWakeMaskCommand, GetMkbpWakeMaskCommand) {
  // Constructor for getting values.
  GetMkbpWakeMaskCommand cmd(EC_MKBP_HOST_EVENT_WAKE_MASK);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_MKBP_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->action, GET_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->mask_type, EC_MKBP_HOST_EVENT_WAKE_MASK);
}

TEST(GetMkbpWakeMaskHostEventCommand, GetMkbpWakeMaskHostEventCommand) {
  GetMkbpWakeMaskHostEventCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_MKBP_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->action, GET_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->mask_type, EC_MKBP_HOST_EVENT_WAKE_MASK);
}

TEST(GetMkbpWakeMaskEventCommand, GetMkbpWakeMaskEventCommand) {
  GetMkbpWakeMaskEventCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_MKBP_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->action, GET_WAKE_MASK);
  EXPECT_EQ(cmd.Req()->mask_type, EC_MKBP_EVENT_WAKE_MASK);
}

// Mock the underlying EcCommand to test.
class GetMkbpWakeMaskCommandTest : public testing::Test {
 public:
  class MockGetMkbpWakeMaskCommand : public GetMkbpWakeMaskCommand {
   public:
    using GetMkbpWakeMaskCommand::GetMkbpWakeMaskCommand;
    MOCK_METHOD(const struct ec_response_mkbp_event_wake_mask*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(GetMkbpWakeMaskCommandTest, Success) {
  MockGetMkbpWakeMaskCommand mock_command(EC_MKBP_HOST_EVENT_WAKE_MASK);
  struct ec_response_mkbp_event_wake_mask response = {
      .wake_mask = EC_HOST_EVENT_MASK(EC_HOST_EVENT_LID_OPEN)};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.GetWakeMask(), 2);
}

// Mock the underlying EcCommand to test.
class GetMkbpWakeMaskHostEventCommandTest : public testing::Test {
 public:
  class MockGetMkbpWakeMaskHostEventCommand
      : public GetMkbpWakeMaskHostEventCommand {
   public:
    using GetMkbpWakeMaskHostEventCommand::GetMkbpWakeMaskHostEventCommand;
    MOCK_METHOD(const struct ec_response_mkbp_event_wake_mask*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(GetMkbpWakeMaskHostEventCommandTest, Success) {
  MockGetMkbpWakeMaskHostEventCommand mock_command;
  struct ec_response_mkbp_event_wake_mask response = {
      .wake_mask = EC_HOST_EVENT_MASK(EC_HOST_EVENT_LID_OPEN)};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(mock_command.IsEnabled(EC_HOST_EVENT_LID_OPEN));
  EXPECT_FALSE(mock_command.IsEnabled(EC_HOST_EVENT_LID_CLOSED));

  EXPECT_EQ(mock_command.GetWakeMask(), 2);
}

// Mock the underlying EcCommand to test.
class GetMkbpWakeMaskEventCommandTest : public testing::Test {
 public:
  class MockGetMkbpWakeMaskEventCommand : public GetMkbpWakeMaskEventCommand {
   public:
    using GetMkbpWakeMaskEventCommand::GetMkbpWakeMaskEventCommand;
    MOCK_METHOD(const struct ec_response_mkbp_event_wake_mask*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(GetMkbpWakeMaskEventCommandTest, Success) {
  MockGetMkbpWakeMaskEventCommand mock_command;
  struct ec_response_mkbp_event_wake_mask response = {
      .wake_mask = EC_HOST_EVENT_MASK(EC_MKBP_EVENT_SWITCH)};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_TRUE(mock_command.IsEnabled(EC_MKBP_EVENT_SWITCH));
  EXPECT_FALSE(mock_command.IsEnabled(EC_MKBP_EVENT_FINGERPRINT));

  EXPECT_EQ(mock_command.GetWakeMask(), 8);
}

}  // namespace
}  // namespace ec
