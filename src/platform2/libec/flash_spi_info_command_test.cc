// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/flash_spi_info_command.h"

namespace ec {
namespace {

using ::testing::Return;

TEST(FlashSpiInfoCommand, FlashSpiInfoCommand) {
  FlashSpiInfoCommand cmd;
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_SPI_INFO);
}

// Mock the underlying EcCommand to test.
class FlashSpiInfoCommandTest : public testing::Test {
 public:
  class MockFlashSpiInfoCommand : public FlashSpiInfoCommand {
   public:
    using FlashSpiInfoCommand::FlashSpiInfoCommand;
    MOCK_METHOD(const struct ec_response_flash_spi_info*,
                Resp,
                (),
                (const, override));
  };
};

TEST_F(FlashSpiInfoCommandTest, Success) {
  MockFlashSpiInfoCommand mock_command;
  struct ec_response_flash_spi_info response = {
      .jedec = {1, 2, 3}, .mfr_dev_id = {4, 5}, .sr1 = 6, .sr2 = 7};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.GetJedecManufacturer(), 1);
  EXPECT_EQ(mock_command.GetJedecDeviceId(), 515);
  EXPECT_EQ(mock_command.GetJedecCapacity(), 8);
  EXPECT_EQ(mock_command.GetManufacturerId(), 4);
  EXPECT_EQ(mock_command.GetDeviceId(), 5);
  EXPECT_EQ(mock_command.GetStatusRegister1(), 6);
  EXPECT_EQ(mock_command.GetStatusRegister2(), 7);
}

}  // namespace
}  // namespace ec
