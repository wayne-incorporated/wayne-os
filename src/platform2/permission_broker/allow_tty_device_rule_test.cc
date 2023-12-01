// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/allow_tty_device_rule.h"
#include "permission_broker/rule_test.h"

#include <gtest/gtest.h>

namespace permission_broker {

class AllowTtyDeviceRuleTest : public RuleTest {
 public:
  AllowTtyDeviceRuleTest() = default;
  AllowTtyDeviceRuleTest(const AllowTtyDeviceRuleTest&) = delete;
  AllowTtyDeviceRuleTest& operator=(const AllowTtyDeviceRuleTest&) = delete;

  ~AllowTtyDeviceRuleTest() override = default;

 protected:
  AllowTtyDeviceRule rule_;
};

TEST_F(AllowTtyDeviceRuleTest, IgnoreNonTtyDevice) {
  ASSERT_EQ(Rule::IGNORE, rule_.ProcessDevice(FindDevice("/dev/null").get()));
}

TEST_F(AllowTtyDeviceRuleTest, AllowTtyDevice) {
  ASSERT_EQ(Rule::ALLOW, rule_.ProcessDevice(FindDevice("/dev/tty").get()));
}

}  // namespace permission_broker
