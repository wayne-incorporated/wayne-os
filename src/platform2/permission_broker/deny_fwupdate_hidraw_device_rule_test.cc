// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_fwupdate_hidraw_device_rule.h"

#include <gtest/gtest.h>
#include <libudev.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "base/strings/string_util.h"
#include "permission_broker/udev_scopers.h"

namespace {

const char kDefaultPath[] = "/devices/wormhole/0000:1234:1500.001/hidraw0";

}  // namespace

namespace permission_broker {

class DenyFwUpdateHidrawDeviceRuleTest : public testing::Test {
 public:
  DenyFwUpdateHidrawDeviceRuleTest() = default;
  DenyFwUpdateHidrawDeviceRuleTest(const DenyFwUpdateHidrawDeviceRuleTest&) =
      delete;
  DenyFwUpdateHidrawDeviceRuleTest& operator=(
      const DenyFwUpdateHidrawDeviceRuleTest&) = delete;

  ~DenyFwUpdateHidrawDeviceRuleTest() override = default;

 protected:
  DenyFwUpdateHidrawDeviceRule rule_;
};

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, AllowEmptyFwDeviceList) {
  RangeListMap fwDevices;
  EXPECT_FALSE(rule_.IsFwUpdateDevice(kDefaultPath, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, AllowEmptyPath) {
  RangeListMap fwDevices;
  EXPECT_FALSE(rule_.IsFwUpdateDevice("", fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, DenyFwDevice) {
  RangeListMap fwDevices = {{0x1234, {{0x1000, 0x2000}}}};

  EXPECT_TRUE(rule_.IsFwUpdateDevice(kDefaultPath, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, DenyFwDeviceRangeInclusive) {
  RangeListMap fwDevices = {{0x1234, {{0x1000, 0x1500}}}};

  EXPECT_TRUE(rule_.IsFwUpdateDevice(kDefaultPath, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, AllowProductIdBlockedVendor) {
  RangeListMap fwDevices = {{0x1234, {{0x3000, 0x4000}}}};

  EXPECT_FALSE(rule_.IsFwUpdateDevice(kDefaultPath, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, DenyDeviceParent) {
  const char path[] =
      "/devices/pci/0000:1234:1500.001/nuerolink/0000:4567:1500.001/hidraw0";
  RangeListMap fwDevices = {{0x1234, {{0x1000, 0x2000}}}};

  EXPECT_TRUE(rule_.IsFwUpdateDevice(path, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, AllowNoVendorProductPath) {
  const char path[] = "/devices/usb/mouse/hidraw0";
  RangeListMap fwDevices = {{0x1234, {{0x1000, 0x2000}}}};

  EXPECT_FALSE(rule_.IsFwUpdateDevice(path, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, DenyNoTrailingPeriod) {
  const char path[] = "/devices/lasers/0000:1234:1500/hidraw0";
  RangeListMap fwDevices = {{0x1234, {{0x1000, 0x2000}}}};

  EXPECT_TRUE(rule_.IsFwUpdateDevice(path, fwDevices));
}

TEST_F(DenyFwUpdateHidrawDeviceRuleTest, AllowCloseMatch) {
  const char path[] = "/devices/lasers/0000:1234:1500:0/hidraw0";
  RangeListMap fwDevices = {{0x1234, {{0x1000, 0x2000}}}};

  EXPECT_FALSE(rule_.IsFwUpdateDevice(path, fwDevices));
}

}  // namespace permission_broker
