// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/pd_chip_info_command.h"

namespace ec {
namespace {

using ::testing::Return;

class MockPdChipInfoCommandV0 : public PdChipInfoCommandV0 {
 public:
  using PdChipInfoCommandV0::PdChipInfoCommandV0;
  MOCK_METHOD(struct ec_response_pd_chip_info*, Resp, (), (const, override));
};

TEST(PdChipInfoCommand, PdChipInfoCommandV0) {
  MockPdChipInfoCommandV0 mock_command(0, 0);
  struct ec_response_pd_chip_info response = {
      .vendor_id = 1, .product_id = 2, .device_id = 3};
  EXPECT_CALL(mock_command, Resp).WillRepeatedly(Return(&response));

  EXPECT_EQ(mock_command.Version(), 0);
  EXPECT_EQ(mock_command.Command(), EC_CMD_PD_CHIP_INFO);
  EXPECT_EQ(mock_command.VendorId(), 1);
  EXPECT_EQ(mock_command.ProductId(), 2);
  EXPECT_EQ(mock_command.DeviceId(), 3);
}

}  // namespace
}  // namespace ec
