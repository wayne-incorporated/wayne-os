// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/i2c_passthru_command.h"

namespace ec {

namespace {

using ::testing::ElementsAreArray;
using ::testing::NiceMock;
using ::testing::Return;

constexpr uint8_t kI2cBus = 5;
constexpr uint8_t kI2cAddr = 0x30;
constexpr size_t kI2cReadLen = 16;
constexpr size_t kI2cResponseHeaderSize = 2;

TEST(I2cPassthruCommand, I2cPassthruCommandWrite) {
  const std::vector<uint8_t> kData{0xaa, 0xbb, 0xcc, 0xdd};
  struct ec_params_i2c_passthru_msg expected_write_info {
    .addr_flags = kI2cAddr, .len = static_cast<uint16_t>(kData.size())
  };
  auto* ptr = reinterpret_cast<uint8_t*>(&expected_write_info);
  std::vector<uint8_t> expected_msg_and_payload(
      ptr, ptr + sizeof(expected_write_info));
  expected_msg_and_payload.insert(expected_msg_and_payload.end(), kData.begin(),
                                  kData.end());

  I2cPassthruCommand cmd(kI2cBus, kI2cAddr, kData, 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_I2C_PASSTHRU);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->req.port, kI2cBus);
  EXPECT_EQ(cmd.Req()->req.num_msgs, 1);
  EXPECT_THAT(expected_msg_and_payload,
              ElementsAreArray(cmd.Req()->msg_and_payload.begin(),
                               expected_msg_and_payload.size()));
  EXPECT_EQ(cmd.RespSize(), kI2cResponseHeaderSize);
}

TEST(I2cPassthruCommand, I2cPassthruCommandRead) {
  struct ec_params_i2c_passthru_msg expected_read_info {
    .addr_flags = kI2cAddr | EC_I2C_FLAG_READ, .len = kI2cReadLen
  };
  auto* ptr = reinterpret_cast<uint8_t*>(&expected_read_info);
  std::vector<uint8_t> expected_msg_and_payload(
      ptr, ptr + sizeof(expected_read_info));

  I2cPassthruCommand cmd(kI2cBus, kI2cAddr, {}, kI2cReadLen);
  EXPECT_EQ(cmd.Command(), EC_CMD_I2C_PASSTHRU);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->req.port, kI2cBus);
  EXPECT_EQ(cmd.Req()->req.num_msgs, 1);
  EXPECT_THAT(expected_msg_and_payload,
              ElementsAreArray(cmd.Req()->msg_and_payload.begin(),
                               expected_msg_and_payload.size()));
  EXPECT_EQ(cmd.RespSize(), kI2cResponseHeaderSize + kI2cReadLen);
}

TEST(I2cPassthruCommand, I2cPassthruCommandWriteAndRead) {
  const std::vector<uint8_t> kData{0xaa, 0xbb, 0xcc, 0xdd};
  struct ec_params_i2c_passthru_msg expected_write_info {
    .addr_flags = kI2cAddr, .len = static_cast<uint16_t>(kData.size())
  };
  struct ec_params_i2c_passthru_msg expected_read_info {
    .addr_flags = kI2cAddr | EC_I2C_FLAG_READ, .len = kI2cReadLen
  };
  auto* write_info_ptr = reinterpret_cast<uint8_t*>(&expected_write_info);
  auto* read_info_ptr = reinterpret_cast<uint8_t*>(&expected_read_info);

  std::vector<uint8_t> expected_msg_and_payload(
      write_info_ptr, write_info_ptr + sizeof(expected_write_info));
  expected_msg_and_payload.insert(expected_msg_and_payload.end(), read_info_ptr,
                                  read_info_ptr + sizeof(expected_read_info));
  expected_msg_and_payload.insert(expected_msg_and_payload.end(), kData.begin(),
                                  kData.end());

  I2cPassthruCommand cmd(kI2cBus, kI2cAddr, kData, kI2cReadLen);
  EXPECT_EQ(cmd.Command(), EC_CMD_I2C_PASSTHRU);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->req.port, kI2cBus);
  EXPECT_EQ(cmd.Req()->req.num_msgs, 2);
  EXPECT_THAT(expected_msg_and_payload,
              ElementsAreArray(cmd.Req()->msg_and_payload.begin(),
                               expected_msg_and_payload.size()));
  EXPECT_EQ(cmd.RespSize(), kI2cResponseHeaderSize + kI2cReadLen);
}

TEST(I2cPassthruCommand, I2cPassthruCommandNoOp) {
  I2cPassthruCommand cmd(kI2cBus, kI2cAddr, {}, 0);
  EXPECT_EQ(cmd.Command(), EC_CMD_I2C_PASSTHRU);
  EXPECT_EQ(cmd.Version(), 0);
  EXPECT_EQ(cmd.Req()->req.port, kI2cBus);
  EXPECT_EQ(cmd.Req()->req.num_msgs, 0);
  EXPECT_EQ(cmd.RespSize(), kI2cResponseHeaderSize);
}

// Mock the underlying EcCommand to test.
class I2cPassthruCommandTest : public testing::Test {
 public:
  class MockI2cPassthruCommand : public I2cPassthruCommand {
   public:
    using I2cPassthruCommand::I2cPassthruCommand;
    MockI2cPassthruCommand() : I2cPassthruCommand(0, 0, {}, 0) {}
    MOCK_METHOD(struct i2c_passthru::Response*, Resp, (), (const, override));
    MOCK_METHOD(uint32_t, RespSize, (), (const, override));
  };
};

TEST_F(I2cPassthruCommandTest, I2cPassthruCommandResponseSucceed) {
  const std::vector<uint8_t> kData{0xaa, 0xbb, 0xcc, 0xdd};
  i2c_passthru::Response response{.resp = {.i2c_status = 0, .num_msgs = 1}};
  std::copy(kData.begin(), kData.end(), response.data.begin());

  NiceMock<MockI2cPassthruCommand> mock_cmd;
  ON_CALL(mock_cmd, Resp).WillByDefault(Return(&response));
  ON_CALL(mock_cmd, RespSize)
      .WillByDefault(Return(kI2cResponseHeaderSize + kData.size()));
  EXPECT_EQ(mock_cmd.I2cStatus(), 0);
  EXPECT_THAT(mock_cmd.RespData(), ElementsAreArray(kData));
}

TEST_F(I2cPassthruCommandTest, I2cPassthruCommandResponseFailed) {
  NiceMock<MockI2cPassthruCommand> mock_cmd;

  i2c_passthru::Response response{
      .resp = {.i2c_status = EC_I2C_STATUS_NAK, .num_msgs = 0}, .data = {}};

  ON_CALL(mock_cmd, Resp).WillByDefault(Return(&response));
  ON_CALL(mock_cmd, RespSize).WillByDefault(Return(kI2cResponseHeaderSize));
  EXPECT_EQ(mock_cmd.I2cStatus(), EC_I2C_STATUS_NAK);
  EXPECT_TRUE(mock_cmd.RespData().empty());
}

}  // namespace

}  // namespace ec
