// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/ec_command.h"
#include "libec/rand_num_command.h"

using testing::Return;

namespace ec {
namespace {

TEST(RandNumCommand, RandNumCommand) {
  RandNumCommand cmd(3);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_RAND_NUM);
  EXPECT_EQ(cmd.Req()->num_rand_bytes, 3);
}

// Mock the underlying EcCommand to test
class RandNumCommandTest : public testing::Test {
 public:
  class MockRandNumCommand : public RandNumCommand {
   public:
    using RandNumCommand::RandNumCommand;
    MOCK_METHOD(const rand::RandNumResp*, Resp, (), (const, override));
  };
};

TEST_F(RandNumCommandTest, GetRandData) {
  MockRandNumCommand mock_command(3);
  struct rand::RandNumResp response = {.rand_num_data = {2, 147, 255}};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.GetRandNumData(), response.rand_num_data);
}

}  // namespace
}  // namespace ec
