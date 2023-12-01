// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libec/pd_chip_info_command.h>

#include "runtime_probe/functions/tcpc.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;

class MockPdChipInfoCommandV0 : public ec::PdChipInfoCommandV0 {
 public:
  MockPdChipInfoCommandV0() : ec::PdChipInfoCommandV0(0, 0) {}

  MOCK_METHOD(bool, Run, (int), (override));
  MOCK_METHOD(const struct ec_response_pd_chip_info*,
              Resp,
              (),
              (const override));
  MOCK_METHOD(uint32_t, Result, (), (const override));
};

class MockTcpcFunction : public TcpcFunction {
  using TcpcFunction::TcpcFunction;

 public:
  MOCK_METHOD(std::unique_ptr<ec::PdChipInfoCommandV0>,
              GetPdChipInfoCommandV0,
              (uint8_t),
              (const override));
  MOCK_METHOD(base::ScopedFD, GetEcDevice, (), (const override));
};

class TcpcFunctionTest : public BaseFunctionTest {};

TEST_F(TcpcFunctionTest, ProbeTcpc) {
  auto probe_function = CreateProbeFunction<MockTcpcFunction>();

  EXPECT_CALL(*probe_function, GetEcDevice())
      .WillOnce(Return(ByMove(base::ScopedFD{})));

  auto cmd0 = std::make_unique<MockPdChipInfoCommandV0>();
  EXPECT_CALL(*cmd0, Run(_)).WillOnce(Return(true));
  struct ec_response_pd_chip_info mock_resp0 {
    .vendor_id = 0xd456, .product_id = 0xc123, .device_id = 0x1
  };
  EXPECT_CALL(*cmd0, Resp()).WillRepeatedly(Return(&mock_resp0));
  EXPECT_CALL(*cmd0, Result()).WillRepeatedly(Return(EC_RES_SUCCESS));
  EXPECT_CALL(*probe_function, GetPdChipInfoCommandV0(0))
      .WillOnce(Return(ByMove(std::move(cmd0))));

  auto cmd1 = std::make_unique<MockPdChipInfoCommandV0>();
  EXPECT_CALL(*cmd1, Run(_)).WillOnce(Return(true));
  struct ec_response_pd_chip_info mock_resp1 {
    .vendor_id = 0xf456, .product_id = 0xe123, .device_id = 0x2
  };
  EXPECT_CALL(*cmd1, Resp()).WillRepeatedly(Return(&mock_resp1));
  EXPECT_CALL(*cmd1, Result()).WillRepeatedly(Return(EC_RES_SUCCESS));
  EXPECT_CALL(*probe_function, GetPdChipInfoCommandV0(1))
      .WillOnce(Return(ByMove(std::move(cmd1))));

  // The last command returns EC_RES_INVALID_PARAM to terminate the probing.
  auto cmd2 = std::make_unique<MockPdChipInfoCommandV0>();
  EXPECT_CALL(*cmd2, Run(_)).WillOnce(Return(true));
  EXPECT_CALL(*cmd2, Result()).WillRepeatedly(Return(EC_RES_INVALID_PARAM));
  EXPECT_CALL(*probe_function, GetPdChipInfoCommandV0(2))
      .WillOnce(Return(ByMove(std::move(cmd2))));

  EXPECT_EQ(probe_function->Eval(), CreateProbeResultFromJson(R"JSON(
    [
      {
        "device_id": "0x1",
        "port": "0",
        "product_id": "0xc123",
        "vendor_id": "0xd456"
      },
      {
        "device_id": "0x2",
        "port": "1",
        "product_id": "0xe123",
        "vendor_id": "0xf456"
      }
    ]
  )JSON"));
}

}  // namespace
}  // namespace runtime_probe
