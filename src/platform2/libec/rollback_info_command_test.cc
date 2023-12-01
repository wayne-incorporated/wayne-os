// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/rollback_info_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(RollbackInfoCommand, RollbackInfoCommand) {
  RollbackInfoCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_ROLLBACK_INFO);
}

// Mock the underlying EcCommand to test.
class RollbackInfoCommandTest : public testing::Test {
 public:
  class MockRollbackInfoCommand : public RollbackInfoCommand {
   public:
    using RollbackInfoCommand::RollbackInfoCommand;
    MOCK_METHOD(const struct ec_response_rollback_info*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(RollbackInfoCommandTest, Success) {
  MockRollbackInfoCommand mock_command;
  struct ec_response_rollback_info response = {
      .id = 3,
      .rollback_min_version = 2,
      .rw_rollback_version = 1,
  };
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.ID(), 3);
  EXPECT_EQ(mock_command.MinVersion(), 2);
  EXPECT_EQ(mock_command.RWVersion(), 1);
}

}  // namespace
}  // namespace ec
