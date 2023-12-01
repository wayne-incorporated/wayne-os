// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/usb_modem_switch_context.h"

#include <memory>
#include <utility>

#include <brillo/udev/mock_udev.h>
#include <brillo/udev/mock_udev_device.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mist/mock_config_loader.h"
#include "mist/mock_context.h"
#include "mist/proto_bindings/usb_modem_info.pb.h"

using testing::_;
using testing::ByMove;
using testing::Return;

namespace mist {

namespace {

const char kFakeDeviceSysPath[] = "/sys/devices/fake/1";
const uint16_t kFakeDeviceBusNumber = 1;
const char kFakeDeviceBusNumberString[] = "1";
const uint16_t kFakeDeviceDeviceAddress = 2;
const char kFakeDeviceDeviceAddressString[] = "2";
const uint16_t kFakeDeviceVendorId = 0x0123;
const char kFakeDeviceVendorIdString[] = "0123";
const uint16_t kFakeDeviceProductId = 0x4567;
const char kFakeDeviceProductIdString[] = "4567";

}  // namespace

TEST(UsbModemSwitchContextTest, InitializeFromSysPath) {
  MockContext context;
  EXPECT_TRUE(context.Initialize());

  auto device = std::make_unique<brillo::MockUdevDevice>();
  EXPECT_CALL(*device, GetSysPath()).WillRepeatedly(Return(kFakeDeviceSysPath));
  EXPECT_CALL(*device, GetSysAttributeValue(_))
      .WillOnce(Return(kFakeDeviceBusNumberString))
      .WillOnce(Return(kFakeDeviceDeviceAddressString))
      .WillOnce(Return(kFakeDeviceVendorIdString))
      .WillOnce(Return(kFakeDeviceProductIdString));
  EXPECT_CALL(*context.GetMockUdev(), CreateDeviceFromSysPath(_))
      .WillOnce(Return(ByMove(std::move(device))));

  UsbModemInfo modem_info;
  EXPECT_CALL(*context.GetMockConfigLoader(),
              GetUsbModemInfo(kFakeDeviceVendorId, kFakeDeviceProductId))
      .WillOnce(Return(&modem_info));

  UsbModemSwitchContext switch_context;
  EXPECT_TRUE(
      switch_context.InitializeFromSysPath(&context, kFakeDeviceSysPath));
  EXPECT_EQ(kFakeDeviceSysPath, switch_context.sys_path());
  EXPECT_EQ(kFakeDeviceBusNumber, switch_context.bus_number());
  EXPECT_EQ(kFakeDeviceDeviceAddress, switch_context.device_address());
  EXPECT_EQ(kFakeDeviceVendorId, switch_context.vendor_id());
  EXPECT_EQ(kFakeDeviceProductId, switch_context.product_id());
  EXPECT_EQ(&modem_info, switch_context.modem_info());
}

}  // namespace mist
