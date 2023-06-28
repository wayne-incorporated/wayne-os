// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/validator_utils.h"

#include <brillo/cryptohome.h>
#include <gtest/gtest.h>

#include "login_manager/proto_bindings/policy_descriptor.pb.h"

using brillo::cryptohome::home::kGuestUserName;

namespace {

constexpr char kValidAccountId[] = "g-account-id";
constexpr char kInvalidAccountId[] = "invalid_account_id";
constexpr char kValidExtensionId[] = "abcdefghijklmnopABCDEFGHIJKLMNOP";
constexpr char kInvalidExtensionId[] = "../../../etc/passwd";

}  // namespace

namespace login_manager {

TEST(ValidatorUtilsTest, EmailAddressTest) {
  EXPECT_TRUE(ValidateEmail("user_who+we.like@some-where.com"));
  EXPECT_TRUE(ValidateEmail("john_doe's_mail@some-where.com"));
  EXPECT_TRUE(ValidateEmail("UPPERCASE_MAIN@some-where.com"));
}

TEST(ValidatorUtilsTest, EmailAddressNonAsciiTest) {
  char invalid[4] = "a@m";
  invalid[2] = static_cast<char>(254);
  EXPECT_FALSE(ValidateEmail(invalid));
}

TEST(ValidatorUtilsTest, EmailAddressNoAtTest) {
  const char no_at[] = "user";
  EXPECT_FALSE(ValidateEmail(no_at));
}

TEST(ValidatorUtilsTest, EmailAddressTooMuchAtTest) {
  const char extra_at[] = "user@what@where";
  EXPECT_FALSE(ValidateEmail(extra_at));
}

TEST(ValidatorUtilsTest, AccountIdKeyTest) {
  EXPECT_TRUE(ValidateAccountIdKey("g-1234567890123456"));
  // email string is invalid GaiaIdKey
  EXPECT_FALSE(ValidateAccountIdKey("john@some.where.com"));
  // Only alphanumeric characters plus a colon are allowed.
  EXPECT_TRUE(ValidateAccountIdKey("g-1234567890"));
  EXPECT_TRUE(ValidateAccountIdKey("g-abcdef0123456789"));
  EXPECT_TRUE(ValidateAccountIdKey("g-ABCDEF0123456789"));
  EXPECT_FALSE(ValidateAccountIdKey("g-123@some.where.com"));
  EXPECT_FALSE(ValidateAccountIdKey("g-123@localhost"));
  // Active Directory account keys.
  EXPECT_TRUE(ValidateAccountIdKey("a-abcdef0123456789"));
  EXPECT_FALSE(ValidateAccountIdKey("a-123@localhost"));
}

TEST(ValidatorUtilsTest, ExtensionIdTest) {
  EXPECT_TRUE(ValidateExtensionId(kValidExtensionId));
  EXPECT_FALSE(ValidateExtensionId(kInvalidExtensionId));
  EXPECT_FALSE(ValidateExtensionId(""));
}

TEST(ValidatorUtilsTest, AccountIdTest) {
  std::string normalized_account_id;
  EXPECT_TRUE(ValidateAccountId(kGuestUserName, &normalized_account_id));
  EXPECT_EQ(kGuestUserName, normalized_account_id);
  EXPECT_TRUE(ValidateAccountId("JOHN@doe.com", &normalized_account_id));
  EXPECT_EQ("john@doe.com", normalized_account_id);
  EXPECT_TRUE(ValidateAccountId(kValidAccountId, &normalized_account_id));
  EXPECT_EQ(kValidAccountId, normalized_account_id);
  EXPECT_FALSE(ValidateAccountId(kInvalidAccountId, &normalized_account_id));
  EXPECT_TRUE(normalized_account_id.empty());
  EXPECT_FALSE(ValidateAccountId("", &normalized_account_id));
  EXPECT_TRUE(normalized_account_id.empty());
}

TEST(ValidatorUtilsTest, PolicyDescriptorDeviceAccountValid) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_DEVICE);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kRetrieve));
}

TEST(ValidatorUtilsTest, PolicyDescriptorDeviceAccountInvalid) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_DEVICE);
  desc.set_account_id(kValidAccountId);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  EXPECT_FALSE(
      ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kRetrieve));
}

TEST(ValidatorUtilsTest, PolicyDescriptorUserAccountValid) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_USER);
  desc.set_account_id(kValidAccountId);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kRetrieve));
}

TEST(ValidatorUtilsTest, PolicyDescriptorUserAccountNoAccountId) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_USER);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
}

TEST(ValidatorUtilsTest, PolicyDescriptorUserAccountInvalidAccountId) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_USER);
  desc.set_account_id(kInvalidAccountId);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  EXPECT_FALSE(
      ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kRetrieve));
}

TEST(ValidatorUtilsTest, PolicyDescriptorSessionlessUserAccountRetrieveOnly) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_SESSIONLESS_USER);
  desc.set_account_id(kValidAccountId);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kRetrieve));
}

TEST(ValidatorUtilsTest, PolicyDescriptorDeviceLocalAccountValid) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT);
  desc.set_account_id(kValidAccountId);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kRetrieve));
}

TEST(ValidatorUtilsTest, PolicyDescriptorChromeDomainValid) {
  PolicyDescriptor desc;
  desc.set_domain(POLICY_DOMAIN_CHROME);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
}

TEST(ValidatorUtilsTest, PolicyDescriptorChromeDomainInvalid) {
  PolicyDescriptor desc;
  desc.set_domain(POLICY_DOMAIN_CHROME);
  desc.set_component_id(kValidExtensionId);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
}

TEST(ValidatorUtilsTest, PolicyDescriptorExtensionDomainValid) {
  PolicyDescriptor desc;
  desc.set_domain(POLICY_DOMAIN_EXTENSIONS);
  desc.set_component_id(kValidExtensionId);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  desc.set_domain(POLICY_DOMAIN_SIGNIN_EXTENSIONS);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
}

TEST(ValidatorUtilsTest, PolicyDescriptorExtensionDomainInvalid) {
  PolicyDescriptor desc;
  desc.set_domain(POLICY_DOMAIN_EXTENSIONS);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  desc.set_domain(POLICY_DOMAIN_SIGNIN_EXTENSIONS);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
}

TEST(ValidatorUtilsTest, PolicyDescriptorExtensionDomainInvalidExtensionId) {
  PolicyDescriptor desc;
  desc.set_domain(POLICY_DOMAIN_EXTENSIONS);
  desc.set_component_id(kInvalidExtensionId);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
  desc.set_domain(POLICY_DOMAIN_SIGNIN_EXTENSIONS);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kStore));
}

TEST(ValidatorUtilsTest, PolicyDescriptorInvalidForChromeDomainAndList) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_DEVICE);
  desc.set_domain(POLICY_DOMAIN_CHROME);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kList));
}

TEST(ValidatorUtilsTest, PolicyDescriptorInvalidForValidComponentIdAndList) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_DEVICE);
  desc.set_domain(POLICY_DOMAIN_EXTENSIONS);
  desc.set_component_id(kValidExtensionId);
  EXPECT_FALSE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kList));
}

TEST(ValidatorUtilsTest, PolicyDescriptorValidForNoComponentIdAndList) {
  PolicyDescriptor desc;
  desc.set_account_type(ACCOUNT_TYPE_DEVICE);
  desc.set_domain(POLICY_DOMAIN_EXTENSIONS);
  EXPECT_TRUE(ValidatePolicyDescriptor(desc, PolicyDescriptorUsage::kList));
}

}  // namespace login_manager
