// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libec/i2c_read_command.h>

#include "runtime_probe/functions/ec_i2c.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::ByMove;
using ::testing::NiceMock;
using ::testing::Return;

// Status codes defined in ec/include/ec_commands.h .
constexpr uint32_t kEcResultSuccess = 0;
constexpr uint32_t kEcResultTimeout = 10;
constexpr uint8_t kEcI2cStatusSuccess = 0;
constexpr uint8_t kEcI2cStatusError = 1;

class EcI2cFunctionTest : public BaseFunctionTest {
 public:
  class MockI2cReadCommand : public ec::I2cReadCommand {
   public:
    MockI2cReadCommand(uint8_t read_len,
                       bool success,
                       uint32_t result,
                       uint8_t i2c_status,
                       uint16_t data)
        : ec::I2cReadCommand(0, 0, 0, read_len) {
      ON_CALL(*this, Run).WillByDefault(Return(success));
      ON_CALL(*this, Result).WillByDefault(Return(result));
      ON_CALL(*this, I2cStatus).WillByDefault(Return(i2c_status));
      ON_CALL(*this, Data).WillByDefault(Return(data));
    }

    MOCK_METHOD(bool, Run, (int), (override));
    MOCK_METHOD(uint16_t, Data, (), (const override));
    MOCK_METHOD(uint32_t, Result, (), (const override));
    MOCK_METHOD(uint8_t, I2cStatus, (), (const override));
  };

  class MockEcI2cFunction : public EcI2cFunction {
    using EcI2cFunction::EcI2cFunction;

   public:
    MOCK_METHOD(std::unique_ptr<ec::I2cReadCommand>,
                GetI2cReadCommand,
                (),
                (const override));
    MOCK_METHOD(base::ScopedFD, GetEcDevice, (), (const override));
  };
};

TEST_F(EcI2cFunctionTest, ProbeSucceed) {
  constexpr auto kResult = 0x2a;  // 42
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 0,
      "chip_addr": 0,
      "data_addr": 0
    }
  )JSON");
  auto probe_function =
      CreateProbeFunction<MockEcI2cFunction>(probe_statement->GetDict());

  EXPECT_CALL(*probe_function, GetEcDevice)
      .WillOnce(Return(ByMove(base::ScopedFD{})));

  auto cmd = std::make_unique<NiceMock<MockI2cReadCommand>>(
      1, true, kEcResultSuccess, kEcI2cStatusSuccess, kResult);
  EXPECT_CALL(*probe_function, GetI2cReadCommand)
      .WillOnce(Return(ByMove(std::move(cmd))));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    [
      {
        "data": 42
      }
    ]
  )JSON"));
}

TEST_F(EcI2cFunctionTest, Probe16bitDataSucceed) {
  constexpr auto kResult = 0x1068;  // 4200
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 0,
      "chip_addr": 0,
      "data_addr": 0,
      "size": 16
    }
  )JSON");
  auto probe_function =
      CreateProbeFunction<MockEcI2cFunction>(probe_statement->GetDict());

  EXPECT_CALL(*probe_function, GetEcDevice)
      .WillOnce(Return(ByMove(base::ScopedFD{})));

  auto cmd = std::make_unique<NiceMock<MockI2cReadCommand>>(
      2, true, kEcResultSuccess, kEcI2cStatusSuccess, kResult);
  EXPECT_CALL(*probe_function, GetI2cReadCommand)
      .WillOnce(Return(ByMove(std::move(cmd))));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    [
      {
        "data": 4200
      }
    ]
  )JSON"));
}

TEST_F(EcI2cFunctionTest, InvalidSize) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 0,
      "chip_addr": 0,
      "data_addr": 0,
      "size": 7
    }
  )JSON");
  EXPECT_FALSE(
      CreateProbeFunction<MockEcI2cFunction>(probe_statement->GetDict()));
}

TEST_F(EcI2cFunctionTest, EcFailed) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 0,
      "chip_addr": 0,
      "data_addr": 0
    }
  )JSON");
  auto probe_function =
      CreateProbeFunction<MockEcI2cFunction>(probe_statement->GetDict());

  EXPECT_CALL(*probe_function, GetEcDevice)
      .WillOnce(Return(ByMove(base::ScopedFD{})));

  auto cmd = std::make_unique<NiceMock<MockI2cReadCommand>>(
      1, false, kEcResultTimeout, kEcI2cStatusSuccess, 0);
  EXPECT_CALL(*cmd, Data).Times(0);
  EXPECT_CALL(*probe_function, GetI2cReadCommand)
      .WillOnce(Return(ByMove(std::move(cmd))));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    []
  )JSON"));
}

TEST_F(EcI2cFunctionTest, EcI2cFailed) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 0,
      "chip_addr": 0,
      "data_addr": 0
    }
  )JSON");
  auto probe_function =
      CreateProbeFunction<MockEcI2cFunction>(probe_statement->GetDict());

  EXPECT_CALL(*probe_function, GetEcDevice)
      .WillOnce(Return(ByMove(base::ScopedFD{})));

  auto cmd = std::make_unique<NiceMock<MockI2cReadCommand>>(
      1, true, kEcResultSuccess, kEcI2cStatusError, 0);
  EXPECT_CALL(*cmd, Data).Times(0);
  EXPECT_CALL(*probe_function, GetI2cReadCommand)
      .WillOnce(Return(ByMove(std::move(cmd))));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    []
  )JSON"));
}

}  // namespace
}  // namespace runtime_probe
