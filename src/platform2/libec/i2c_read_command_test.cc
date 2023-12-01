// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/i2c_passthru_params.h"
#include "libec/i2c_read_command.h"

namespace ec {

namespace {

using ::testing::NiceMock;
using ::testing::Return;

constexpr uint8_t kI2cBus = 5;
constexpr uint8_t kI2cAddr = 0x30;
constexpr uint8_t kI2cOffset = 0x20;
constexpr size_t kI2cResponseHeaderSize = 2;

TEST(I2cReadCommand, I2cReadCommand) {
  constexpr uint8_t kReadLen[] = {1, 2};
  for (auto read_len : kReadLen) {
    auto cmd = I2cReadCommand::Create(kI2cBus, kI2cAddr, kI2cOffset, read_len);
    EXPECT_EQ(cmd->Command(), EC_CMD_I2C_PASSTHRU);
    EXPECT_EQ(cmd->Version(), 0);
    EXPECT_EQ(cmd->Req()->req.port, kI2cBus);
    EXPECT_EQ(cmd->RespSize(), kI2cResponseHeaderSize + read_len);
  }
}

TEST(I2cReadCommand, InvalidReadLen) {
  constexpr uint8_t kInvalidReadLen = 100;
  EXPECT_FALSE(
      I2cReadCommand::Create(kI2cBus, kI2cAddr, kI2cOffset, kInvalidReadLen));
}

// Mock the underlying EcCommand to test.
class I2cReadCommandTest : public testing::Test {
 public:
  class MockI2cReadCommand : public I2cReadCommand {
   public:
    using I2cReadCommand::I2cReadCommand;
    MOCK_METHOD(struct i2c_passthru::Response*, Resp, (), (const, override));
    MOCK_METHOD(uint32_t, RespSize, (), (const, override));
  };
};

TEST_F(I2cReadCommandTest, ReadOneByteSucceed) {
  i2c_passthru::Response response{.resp = {.i2c_status = 0, .num_msgs = 1},
                                  .data = {0x0a}};
  constexpr uint8_t kReadLen = 1;
  auto mock_cmd =
      I2cReadCommand::Create<NiceMock<MockI2cReadCommand>>(0, 0, 0, kReadLen);
  ON_CALL(*mock_cmd, Resp).WillByDefault(Return(&response));
  ON_CALL(*mock_cmd, RespSize)
      .WillByDefault(Return(kI2cResponseHeaderSize + kReadLen));
  EXPECT_EQ(mock_cmd->Data(), 0x0a);
}

TEST_F(I2cReadCommandTest, ReadTwoBytesSucceed) {
  i2c_passthru::Response response{.resp = {.i2c_status = 0, .num_msgs = 1},
                                  .data = {0x0a, 0x0b}};
  constexpr uint8_t kReadLen = 2;
  auto mock_cmd =
      I2cReadCommand::Create<NiceMock<MockI2cReadCommand>>(0, 0, 0, kReadLen);
  ON_CALL(*mock_cmd, Resp).WillByDefault(Return(&response));
  ON_CALL(*mock_cmd, RespSize)
      .WillByDefault(Return(kI2cResponseHeaderSize + kReadLen));
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  EXPECT_EQ(mock_cmd->Data(), 0x0b0a);
#else
  EXPECT_EQ(mock_cmd->Data(), 0x0a0b);
#endif
}

TEST_F(I2cReadCommandTest, ReadFailedWithStatus) {
  auto mock_cmd =
      I2cReadCommand::Create<NiceMock<MockI2cReadCommand>>(0, 0, 0, 1);

  i2c_passthru::Response response{
      .resp = {.i2c_status = EC_I2C_STATUS_NAK, .num_msgs = 0}, .data = {}};

  ON_CALL(*mock_cmd, Resp).WillByDefault(Return(&response));
  EXPECT_EQ(mock_cmd->I2cStatus(), EC_I2C_STATUS_NAK);
}

}  // namespace

}  // namespace ec
