// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "authpolicy/policy/policy_encoder_test_base.h"
#include "authpolicy/policy/user_policy_encoder.h"
#include "bindings/cloud_policy.pb.h"
#include "bindings/policy_constants.h"

namespace em = enterprise_management;

namespace policy {
namespace {

// Converts a repeated string field to a vector.
std::vector<std::string> ToVector(
    const google::protobuf::RepeatedPtrField<std::string>& repeated_field) {
  return std::vector<std::string>(repeated_field.begin(), repeated_field.end());
}

}  // namespace

// Checks whether all user policies are properly encoded from RegistryDict into
// em::CloudPolicySettings.
class UserPolicyEncoderTest
    : public PolicyEncoderTestBase<em::CloudPolicySettings> {
 public:
  UserPolicyEncoderTest() {}
  UserPolicyEncoderTest(const UserPolicyEncoderTest&) = delete;
  UserPolicyEncoderTest& operator=(const UserPolicyEncoderTest&) = delete;
  ~UserPolicyEncoderTest() override {}

 protected:
  void EncodeDict(em::CloudPolicySettings* policy,
                  const RegistryDict* dict) override {
    UserPolicyEncoder encoder(dict, policy_level_);
    *policy = em::CloudPolicySettings();
    encoder.EncodePolicy(policy);
  }

  PolicyLevel policy_level_ = POLICY_LEVEL_MANDATORY;
};

TEST_F(UserPolicyEncoderTest, TestEncodingBoolean) {
  // Note that kStringList can't be constexpr, so we put them all here.
  const bool kBool = true;

  em::CloudPolicySettings policy;

  for (const BooleanPolicyAccess& access : kBooleanPolicyAccess) {
    EncodeBoolean(&policy, access.policy_key, kBool);
    EXPECT_EQ(kBool, access.mutable_proto_ptr(&policy)->value());
  }
}

TEST_F(UserPolicyEncoderTest, TestEncodingInteger) {
  const int kInt = 123;
  em::CloudPolicySettings policy;

  for (const IntegerPolicyAccess& access : kIntegerPolicyAccess) {
    EncodeInteger(&policy, access.policy_key, kInt);
    EXPECT_EQ(kInt, access.mutable_proto_ptr(&policy)->value());
  }
}

TEST_F(UserPolicyEncoderTest, TestEncodingString) {
  const std::string kString = "val1";
  em::CloudPolicySettings policy;

  for (const StringPolicyAccess& access : kStringPolicyAccess) {
    EncodeString(&policy, access.policy_key, kString);
    EXPECT_EQ(kString, access.mutable_proto_ptr(&policy)->value());
  }
}

TEST_F(UserPolicyEncoderTest, TestEncodingStringList) {
  const std::vector<std::string> kStringList = {"val1", "val2", "val3"};
  em::CloudPolicySettings policy;

  for (const StringListPolicyAccess& access : kStringListPolicyAccess) {
    EncodeStringList(&policy, access.policy_key, kStringList);
    EXPECT_EQ(kStringList,
              ToVector(access.mutable_proto_ptr(&policy)->value().entries()));
  }
}

TEST_F(UserPolicyEncoderTest, TestEncodingPolicyLevel) {
  em::CloudPolicySettings policy;

  policy_level_ = POLICY_LEVEL_RECOMMENDED;
  EncodeBoolean(&policy, key::kSearchSuggestEnabled, true);
  EXPECT_EQ(em::PolicyOptions_PolicyMode_RECOMMENDED,
            policy.searchsuggestenabled().policy_options().mode());

  policy_level_ = POLICY_LEVEL_MANDATORY;
  EncodeBoolean(&policy, key::kSearchSuggestEnabled, true);
  EXPECT_EQ(em::PolicyOptions_PolicyMode_MANDATORY,
            policy.searchsuggestenabled().policy_options().mode());
}

}  // namespace policy
