// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/ec_command.h"
#include "libec/flash_info_command.h"

using testing::Return;

namespace ec {
namespace {

TEST(FlashInfoCommand, FlashInfoCommand_v0) {
  FlashInfoCommand_v0 cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_INFO);
}

TEST(FlashInfoCommand, FlashInfoCommand_v1) {
  FlashInfoCommand_v1 cmd;
  EXPECT_EQ(cmd.Version(), 1);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_INFO);
}

TEST(FlashInfoCommand, FlashInfoCommand_v2) {
  FlashInfoCommand_v2 cmd;
  EXPECT_EQ(cmd.Version(), 2);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_INFO);
  EXPECT_EQ(cmd.Req()->num_banks_desc, 0);
}

// Mock the underlying EcCommand to test
class FlashInfoCommand_v2Test : public testing::Test {
 public:
  class MockFlashInfoCommand_v2 : public FlashInfoCommand_v2 {
   public:
    using FlashInfoCommand_v2::FlashInfoCommand_v2;
    MOCK_METHOD(bool, EcCommandRun, (int fd), (override));
    MOCK_METHOD(const flash_info::Params_v2*, Resp, (), (const, override));
    MOCK_METHOD(uint32_t, Result, (), (const, override));
  };
};

TEST_F(FlashInfoCommand_v2Test, Success) {
  flash_info::Params_v2 response;
  MockFlashInfoCommand_v2 mock_command;

  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));
  EXPECT_CALL(mock_command, Result).WillRepeatedly(Return(EC_RES_SUCCESS));

  EXPECT_CALL(mock_command, EcCommandRun)
      .WillOnce([&response](int fd) {
        response = {.info = {.num_banks_total = 2}};
        return true;
      })
      .WillOnce([&response](int fd) {
        response = {.info = {
                        .flash_size = 1024,
                        .flags = 0,
                        .write_ideal_size = 10,
                        .num_banks_total = 2,
                        .num_banks_desc = 2,
                    }};
        response.banks[0] = {.count = 1,
                             .size_exp = 1,
                             .write_size_exp = 1,
                             .erase_size_exp = 1,
                             .protect_size_exp = 1};
        response.banks[1] = {.count = 2,
                             .size_exp = 2,
                             .write_size_exp = 2,
                             .erase_size_exp = 2,
                             .protect_size_exp = 2};
        return true;
      });
  EXPECT_TRUE(mock_command.Run(-1));

  EXPECT_EQ(mock_command.GetTotalNumBanks(), 2);
  EXPECT_EQ(mock_command.GetIdealWriteSize(), 10);
  EXPECT_EQ(mock_command.GetFlashSize(), 1024);
  EXPECT_EQ(mock_command.FlashErasesToZero(), false);
  EXPECT_EQ(mock_command.FlashSelectRequired(), false);
  struct ec_flash_bank expected_bank0 = {.count = 1,
                                         .size_exp = 1,
                                         .write_size_exp = 1,
                                         .erase_size_exp = 1,
                                         .protect_size_exp = 1};
  EXPECT_EQ(*mock_command.GetBankDescription(0), expected_bank0);
  struct ec_flash_bank expected_bank1 = {.count = 2,
                                         .size_exp = 2,
                                         .write_size_exp = 2,
                                         .erase_size_exp = 2,
                                         .protect_size_exp = 2};
  EXPECT_EQ(*mock_command.GetBankDescription(1), expected_bank1);
  EXPECT_EQ(mock_command.GetBankDescription(2), std::nullopt);
}

}  // namespace
}  // namespace ec
