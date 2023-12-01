// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_usb_device_class_rule.h"
#include "permission_broker/rule_test.h"

#include <gtest/gtest.h>
#include <linux/usb/ch9.h>

namespace permission_broker {

class DenyUsbDeviceClassRuleTest : public RuleTest {
 public:
  DenyUsbDeviceClassRuleTest() : rule_(USB_CLASS_HUB) {}
  DenyUsbDeviceClassRuleTest(const DenyUsbDeviceClassRuleTest&) = delete;
  DenyUsbDeviceClassRuleTest& operator=(const DenyUsbDeviceClassRuleTest&) =
      delete;

  ~DenyUsbDeviceClassRuleTest() override = default;

 protected:
  DenyUsbDeviceClassRule rule_;
};

TEST_F(DenyUsbDeviceClassRuleTest, IgnoreNonUsbDevice) {
  ASSERT_EQ(Rule::IGNORE, rule_.ProcessDevice(FindDevice("/dev/null").get()));
}

TEST_F(DenyUsbDeviceClassRuleTest, DISABLED_DenyMatchingUsbDevice) {
  ASSERT_EQ(Rule::DENY,
            rule_.ProcessDevice(FindDevice("/dev/bus/usb/001/001").get()));
}

}  // namespace permission_broker
