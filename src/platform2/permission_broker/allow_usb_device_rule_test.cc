// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/allow_usb_device_rule.h"
#include "permission_broker/rule_test.h"

#include <gtest/gtest.h>

namespace permission_broker {

class AllowUsbDeviceRuleTest : public RuleTest {
 public:
  AllowUsbDeviceRuleTest() = default;
  AllowUsbDeviceRuleTest(const AllowUsbDeviceRuleTest&) = delete;
  AllowUsbDeviceRuleTest& operator=(const AllowUsbDeviceRuleTest&) = delete;

  ~AllowUsbDeviceRuleTest() override = default;

 protected:
  AllowUsbDeviceRule rule_;
};

TEST_F(AllowUsbDeviceRuleTest, IgnoreNonUsbDevice) {
  ASSERT_EQ(Rule::IGNORE, rule_.ProcessDevice(FindDevice("/dev/null").get()));
}

TEST_F(AllowUsbDeviceRuleTest, DISABLED_AllowUsbDevice) {
  ASSERT_EQ(Rule::ALLOW,
            rule_.ProcessDevice(FindDevice("/dev/bus/usb/001/001").get()));
}

}  // namespace permission_broker
