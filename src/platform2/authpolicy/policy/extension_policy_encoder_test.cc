// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "authpolicy/policy/extension_policy_encoder.h"
#include "authpolicy/policy/policy_encoder_test_base.h"
#include "bindings/authpolicy_containers.pb.h"

namespace {
constexpr char kValidExtensionId[] = "abcdeFGHabcdefghAbcdefGhabcdEfgh";
constexpr char kTooShortExtensionId[] = "abcdeFGHabcdefgh";
constexpr char kBadCharsExtensionId[] = "TheQuickBrownFoxJumpsOverTheOryx";

constexpr char kMandatoryKey[] = "Policy";
constexpr char kRecommendedKey[] = "Recommended";
}  // namespace

namespace policy {

class ExtensionPolicyEncoderTest
    : public PolicyEncoderTestBase<ExtensionPolicies> {
 public:
  ExtensionPolicyEncoderTest() = default;
  ExtensionPolicyEncoderTest(const ExtensionPolicyEncoderTest&) = delete;
  ExtensionPolicyEncoderTest& operator=(const ExtensionPolicyEncoderTest&) =
      delete;

  ~ExtensionPolicyEncoderTest() override = default;

 protected:
  void EncodeDict(ExtensionPolicies* policy,
                  const RegistryDict* dict) override {
    ExtensionPolicyEncoder encoder(dict);
    policy->clear();
    encoder.EncodePolicy(policy);
  }
};

// Test encoding with "<extension_id>\\Policy" registry path for mandatory
// policies.
TEST_F(ExtensionPolicyEncoderTest, TestEncoding) {
  // Make sure the registry key path contains the extension id and the mandatory
  // or recommended key.
  ExtensionPolicies policies;

  SetPath({kValidExtensionId, kMandatoryKey});
  EncodeBoolean(&policies, "policy1", true);
  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kValidExtensionId, policies[0].id());
  EXPECT_EQ("{\"Policy\":{\"policy1\":true}}", policies[0].json_data());

  EncodeInteger(&policies, "policy2", 123);
  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kValidExtensionId, policies[0].id());
  EXPECT_EQ("{\"Policy\":{\"policy2\":123}}", policies[0].json_data());

  EncodeString(&policies, "policy3", "val1");
  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kValidExtensionId, policies[0].id());
  EXPECT_EQ("{\"Policy\":{\"policy3\":\"val1\"}}", policies[0].json_data());

  EncodeStringList(&policies, "policy4", {"val1", "val2", "val3"});
  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kValidExtensionId, policies[0].id());
  EXPECT_EQ(
      "{\"Policy\":{\"policy4\":{\"1\":\"val1\",\"2\":\"val2\",\"3\":\"val3\"}}"
      "}",
      policies[0].json_data());
}

// Test that a "<bad_extension_id>\\Policy" registry path is ignored.
TEST_F(ExtensionPolicyEncoderTest, BadExtensionsIdFails) {
  ExtensionPolicies policies;

  SetPath({kTooShortExtensionId, kMandatoryKey});
  EncodeBoolean(&policies, "testpolicy", true);
  EXPECT_EQ(0, policies.size());

  SetPath({kBadCharsExtensionId, kMandatoryKey});
  EncodeBoolean(&policies, "testpolicy", true);
  EXPECT_EQ(0, policies.size());
}

// Test "<extension_id>\\Recommended" registry path. In fact, anything after a
// valid extension id works and will be filtered out later in Chrome.
TEST_F(ExtensionPolicyEncoderTest, RecommendedKey) {
  ExtensionPolicies policies;

  SetPath({kValidExtensionId, kRecommendedKey});
  EncodeBoolean(&policies, "policy1", true);
  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kValidExtensionId, policies[0].id());
  EXPECT_EQ("{\"Recommended\":{\"policy1\":true}}", policies[0].json_data());
}

}  // namespace policy
