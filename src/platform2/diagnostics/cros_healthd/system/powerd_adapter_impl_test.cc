// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/dbus-proxy-mocks.h>

#include "diagnostics/cros_healthd/system/powerd_adapter_impl.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::WithArg;

namespace diagnostics {
namespace {

class PowerdAdapterImplTest : public ::testing::Test {
 public:
  PowerdAdapterImplTest() = default;
  PowerdAdapterImplTest(const PowerdAdapterImplTest&) = delete;
  PowerdAdapterImplTest& operator=(const PowerdAdapterImplTest&) = delete;

 protected:
  StrictMock<org::chromium::PowerManagerProxyMock> power_manager_proxy_;
  PowerdAdapterImpl powerd_adapter_{&power_manager_proxy_};
};

TEST_F(PowerdAdapterImplTest, PowerSupplySuccess) {
  power_manager::PowerSupplyProperties power_supply_proto;
  EXPECT_CALL(power_manager_proxy_, GetPowerSupplyProperties(_, _, _))
      .WillOnce(WithArg<0>([&power_supply_proto](std::vector<uint8_t>* out) {
        out->resize(power_supply_proto.ByteSizeLong());
        power_supply_proto.SerializeToArray(out->data(), out->size());
        return true;
      }));

  auto response = powerd_adapter_.GetPowerSupplyProperties();
  EXPECT_TRUE(response);
  // The proto structure is simple enough where it can be compared as a string.
  // If if becomes more complex this will need to change.
  EXPECT_EQ(response.value().SerializeAsString(),
            power_supply_proto.SerializeAsString());
}

TEST_F(PowerdAdapterImplTest, PowerSupplyFail) {
  EXPECT_CALL(power_manager_proxy_, GetPowerSupplyProperties(_, _, _))
      .WillOnce(Return(false));

  ASSERT_EQ(powerd_adapter_.GetPowerSupplyProperties(), std::nullopt);
}

TEST_F(PowerdAdapterImplTest, PowerSupplyParseError) {
  // 0x07 -> wire_type=7. 7 is not a valid wire_type.
  std::vector<uint8_t> malformed_message{0x07};
  EXPECT_CALL(power_manager_proxy_, GetPowerSupplyProperties(_, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(malformed_message), Return(true)));

  ASSERT_EQ(powerd_adapter_.GetPowerSupplyProperties(), std::nullopt);
}

}  // namespace
}  // namespace diagnostics
