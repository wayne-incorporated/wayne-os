// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_usb_vendor_id_rule.h"
#include "permission_broker/rule_test.h"

#include <gtest/gtest.h>

static const uint16_t kLinuxFoundationUsbVendorId = 0x1d6b;

namespace permission_broker {

class DenyUsbVendorIdRuleTest : public RuleTest {
 public:
  DenyUsbVendorIdRuleTest() : rule_(kLinuxFoundationUsbVendorId) {}
  DenyUsbVendorIdRuleTest(const DenyUsbVendorIdRuleTest&) = delete;
  DenyUsbVendorIdRuleTest& operator=(const DenyUsbVendorIdRuleTest&) = delete;

  ~DenyUsbVendorIdRuleTest() override = default;

 protected:
  DenyUsbVendorIdRule rule_;
};

TEST_F(DenyUsbVendorIdRuleTest, IgnoreNonUsbDevice) {
  ASSERT_EQ(Rule::IGNORE, rule_.ProcessDevice(FindDevice("/dev/null").get()));
}

TEST_F(DenyUsbVendorIdRuleTest, DISABLED_DenyMatchingUsbDevice) {
  ASSERT_EQ(Rule::DENY,
            rule_.ProcessDevice(FindDevice("/dev/bus/usb/001/001").get()));
}

}  // namespace permission_broker
