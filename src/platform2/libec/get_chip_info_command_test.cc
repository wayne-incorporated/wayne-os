// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/get_chip_info_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(GetChipInfoCommand, GetChipInfoCommand) {
  GetChipInfoCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_GET_CHIP_INFO);
}

// Mock the underlying EcCommand to test.
class GetChipInfoCommandTest : public testing::Test {
 public:
  class MockGetChipInfoCommand : public GetChipInfoCommand {
   public:
    using GetChipInfoCommand::GetChipInfoCommand;
    MOCK_METHOD(struct ec_response_get_chip_info*, Resp, (), (override));
    MOCK_METHOD(bool, EcCommandRun, (int fd), (override));
  };
};

TEST_F(GetChipInfoCommandTest, Success) {
  MockGetChipInfoCommand mock_command;
  struct ec_response_get_chip_info response = {
      .vendor = "vendor", .name = "name", .revision = "revision"};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));

  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.name(), "name");
  EXPECT_EQ(mock_command.revision(), "revision");
  EXPECT_EQ(mock_command.vendor(), "vendor");
}

TEST_F(GetChipInfoCommandTest, NameNotNullTerminated) {
  MockGetChipInfoCommand mock_command;
  struct ec_response_get_chip_info response {};
  std::fill(response.name, response.name + sizeof(response.name), 'a');
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));
  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.name(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

TEST_F(GetChipInfoCommandTest, RevisionNotNullTerminated) {
  MockGetChipInfoCommand mock_command;
  struct ec_response_get_chip_info response {};
  std::fill(response.revision, response.revision + sizeof(response.revision),
            'a');
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));
  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.revision(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

TEST_F(GetChipInfoCommandTest, VendorNotNullTerminated) {
  MockGetChipInfoCommand mock_command;
  struct ec_response_get_chip_info response {};
  std::fill(response.vendor, response.vendor + sizeof(response.vendor), 'a');
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));
  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.vendor(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

}  // namespace
}  // namespace ec
