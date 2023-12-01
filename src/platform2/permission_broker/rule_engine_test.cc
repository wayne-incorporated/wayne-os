// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/rule_engine.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

#include "permission_broker/rule.h"

using std::string;
using ::testing::_;
using ::testing::Return;

namespace permission_broker {

class MockRule : public Rule {
 public:
  MockRule() : Rule("MockRule") {}
  MockRule(const MockRule&) = delete;
  MockRule& operator=(const MockRule&) = delete;

  ~MockRule() override = default;

  MOCK_METHOD(Result, ProcessDevice, (udev_device * device), (override));
};

class MockRuleEngine : public RuleEngine {
 public:
  MockRuleEngine() = default;
  MockRuleEngine(const MockRuleEngine&) = delete;
  MockRuleEngine& operator=(const MockRuleEngine&) = delete;

  ~MockRuleEngine() override = default;

  MOCK_METHOD(void, WaitForEmptyUdevQueue, (), (override));
};

class RuleEngineTest : public testing::Test {
 public:
  RuleEngineTest() = default;
  RuleEngineTest(const RuleEngineTest&) = delete;
  RuleEngineTest& operator=(const RuleEngineTest&) = delete;

  ~RuleEngineTest() override = default;

  Rule::Result ProcessPath(const string& path) {
    return engine_.ProcessPath(path);
  }

 protected:
  Rule* CreateMockRule(const Rule::Result result) const {
    MockRule* rule = new MockRule();
    EXPECT_CALL(*rule, ProcessDevice(_)).WillOnce(Return(result));
    return rule;
  }

  MockRuleEngine engine_;
};

TEST_F(RuleEngineTest, EmptyRuleChain) {
  EXPECT_EQ(Rule::IGNORE, ProcessPath("/dev/null"));
}

TEST_F(RuleEngineTest, AllowAccess) {
  engine_.AddRule(CreateMockRule(Rule::ALLOW));
  EXPECT_EQ(Rule::ALLOW, ProcessPath("/dev/null"));
}

TEST_F(RuleEngineTest, DenyAccess) {
  engine_.AddRule(CreateMockRule(Rule::DENY));
  EXPECT_EQ(Rule::DENY, ProcessPath("/dev/null"));
}

TEST_F(RuleEngineTest, DenyPrecedence) {
  engine_.AddRule(CreateMockRule(Rule::ALLOW));
  engine_.AddRule(CreateMockRule(Rule::IGNORE));
  engine_.AddRule(CreateMockRule(Rule::DENY));
  EXPECT_EQ(Rule::DENY, ProcessPath("/dev/null"));
}

TEST_F(RuleEngineTest, AllowPrecedence) {
  engine_.AddRule(CreateMockRule(Rule::IGNORE));
  engine_.AddRule(CreateMockRule(Rule::ALLOW));
  engine_.AddRule(CreateMockRule(Rule::IGNORE));
  EXPECT_EQ(Rule::ALLOW, ProcessPath("/dev/null"));
}

TEST_F(RuleEngineTest, LockdownPrecedence) {
  engine_.AddRule(CreateMockRule(Rule::IGNORE));
  engine_.AddRule(CreateMockRule(Rule::ALLOW_WITH_LOCKDOWN));
  engine_.AddRule(CreateMockRule(Rule::ALLOW));
  EXPECT_EQ(Rule::ALLOW_WITH_LOCKDOWN, ProcessPath("/dev/null"));
}

TEST_F(RuleEngineTest, DetachPrecedence) {
  engine_.AddRule(CreateMockRule(Rule::IGNORE));
  engine_.AddRule(CreateMockRule(Rule::ALLOW_WITH_DETACH));
  engine_.AddRule(CreateMockRule(Rule::ALLOW));
  EXPECT_EQ(Rule::ALLOW_WITH_DETACH, ProcessPath("/dev/null"));
}

}  // namespace permission_broker
