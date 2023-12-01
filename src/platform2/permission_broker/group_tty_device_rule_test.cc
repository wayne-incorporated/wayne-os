// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "permission_broker/allow_group_tty_device_rule.h"
#include "permission_broker/deny_group_tty_device_rule.h"
#include "permission_broker/rule_test.h"

namespace permission_broker {

class GroupTtyDeviceRuleTest : public RuleTest {
 public:
  GroupTtyDeviceRuleTest()
      : allow_rule_("nonexistent"), deny_rule_("nonexistent") {}
  GroupTtyDeviceRuleTest(const GroupTtyDeviceRuleTest&) = delete;
  GroupTtyDeviceRuleTest& operator=(const GroupTtyDeviceRuleTest&) = delete;

  ~GroupTtyDeviceRuleTest() override = default;

 protected:
  AllowGroupTtyDeviceRule allow_rule_;
  DenyGroupTtyDeviceRule deny_rule_;
};

TEST_F(GroupTtyDeviceRuleTest, AllowRuleIgnoreNonMatchingGroup) {
  ASSERT_EQ(Rule::IGNORE,
            allow_rule_.ProcessDevice(FindDevice("/dev/tty").get()));
}

TEST_F(GroupTtyDeviceRuleTest, DenyRuleIgnoreNonMatchingGroup) {
  ASSERT_EQ(Rule::IGNORE,
            deny_rule_.ProcessDevice(FindDevice("/dev/tty").get()));
}

}  // namespace permission_broker
