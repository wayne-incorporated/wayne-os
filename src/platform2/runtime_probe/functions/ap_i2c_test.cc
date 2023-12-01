// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/json/json_reader.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include "runtime_probe/functions/ap_i2c.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::A;
using ::testing::Return;

class ApI2cFunctionTest : public BaseFunctionTest {};

TEST_F(ApI2cFunctionTest, ProbeSucceed) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 1,
      "chip_addr": 2,
      "data_addr": 3
    }
  )JSON");
  SetFile("/dev/i2c-1", "");

  auto probe_function =
      CreateProbeFunction<ApI2cFunction>(probe_statement->GetDict());

  auto syscaller = mock_context()->mock_syscaller();
  EXPECT_CALL(*syscaller, Ioctl(_, I2C_SLAVE_FORCE, 2)).WillOnce(Return(0));
  EXPECT_CALL(*syscaller, Ioctl(_, I2C_SMBUS, A<void*>()))
      .WillOnce([](int, unsigned long, void* data) {  // NOLINT(runtime/int)
        auto* ioctl_data = static_cast<i2c_smbus_ioctl_data*>(data);
        ioctl_data->data->byte = 0x2a;  // 42
        return 0;
      });

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    [
      {
        "data": 42
      }
    ]
  )JSON"));
}

TEST_F(ApI2cFunctionTest, InvalidArgument) {
  // i2c_bus should be an integer greater than 0.
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": -1,
      "chip_addr": 2,
      "data_addr": 3
    }
  )JSON");

  auto probe_function =
      CreateProbeFunction<ApI2cFunction>(probe_statement->GetDict());

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    []
  )JSON"));
}

TEST_F(ApI2cFunctionTest, OpenI2cFileFailed) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 1,
      "chip_addr": 2,
      "data_addr": 3
    }
  )JSON");

  auto probe_function =
      CreateProbeFunction<ApI2cFunction>(probe_statement->GetDict());

  // File "/dev/i2c-1" doesn't exist.
  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    []
  )JSON"));
}

TEST_F(ApI2cFunctionTest, SetChipAddrFailed) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 1,
      "chip_addr": 2,
      "data_addr": 3
    }
  )JSON");
  SetFile("/dev/i2c-1", "");

  auto probe_function =
      CreateProbeFunction<ApI2cFunction>(probe_statement->GetDict());

  auto syscaller = mock_context()->mock_syscaller();
  EXPECT_CALL(*syscaller, Ioctl(_, I2C_SLAVE_FORCE, 2)).WillOnce(Return(-1));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    []
  )JSON"));
}

TEST_F(ApI2cFunctionTest, ReadI2cDataFailed) {
  auto probe_statement = base::JSONReader::Read(R"JSON(
    {
      "i2c_bus": 1,
      "chip_addr": 2,
      "data_addr": 3
    }
  )JSON");
  SetFile("/dev/i2c-1", "");

  auto probe_function =
      CreateProbeFunction<ApI2cFunction>(probe_statement->GetDict());

  auto syscaller = mock_context()->mock_syscaller();
  EXPECT_CALL(*syscaller, Ioctl(_, I2C_SLAVE_FORCE, 2)).WillOnce(Return(0));
  EXPECT_CALL(*syscaller, Ioctl(_, I2C_SMBUS, A<void*>())).WillOnce(Return(-1));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    []
  )JSON"));
}

}  // namespace
}  // namespace runtime_probe
