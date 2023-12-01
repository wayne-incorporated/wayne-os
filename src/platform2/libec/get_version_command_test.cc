// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/get_version_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(GetVersionCommand, GetVersionCommand) {
  GetVersionCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_GET_VERSION);
}

// Mock the underlying EcCommand to test.
class GetVersionCommandTest : public testing::Test {
 public:
  class MockGetVersionCommand : public GetVersionCommand {
   public:
    using GetVersionCommand::GetVersionCommand;
    MOCK_METHOD(struct ec_response_get_version*, Resp, (), (override));
    MOCK_METHOD(bool, EcCommandRun, (int fd), (override));
  };
};

TEST_F(GetVersionCommandTest, Success) {
  MockGetVersionCommand mock_command;
  struct ec_response_get_version response = {.version_string_ro = "ro_version",
                                             .version_string_rw = "rw_version",
                                             .current_image = EC_IMAGE_RW};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));

  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.ROVersion(), "ro_version");
  EXPECT_EQ(mock_command.RWVersion(), "rw_version");
  EXPECT_EQ(mock_command.Image(), EC_IMAGE_RW);
}

TEST_F(GetVersionCommandTest, ROVersionNotNullTerminated) {
  MockGetVersionCommand mock_command;
  struct ec_response_get_version response {};
  std::fill(response.version_string_ro,
            response.version_string_ro + sizeof(response.version_string_ro),
            'a');
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));
  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.ROVersion(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

TEST_F(GetVersionCommandTest, RWVersionNotNullTerminated) {
  MockGetVersionCommand mock_command;
  struct ec_response_get_version response {};
  std::fill(response.version_string_rw,
            response.version_string_rw + sizeof(response.version_string_rw),
            'a');
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, EcCommandRun).WillOnce(Return(true));
  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.RWVersion(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

}  // namespace
}  // namespace ec
