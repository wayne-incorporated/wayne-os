// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "policy/device_local_account_policy_util.h"

namespace em = enterprise_management;

namespace policy {

// All CanonicalizeEmail tests are copied from -
// https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gaia/gaia_auth_util_unittest.cc
TEST(EphemeralUtilTest, EmailAddressNoOp) {
  const char lower_case[] = "user@what.com";
  EXPECT_EQ(lower_case, CanonicalizeEmail(lower_case));
}

TEST(EphemeralUtilTest, InvalidEmailAddress) {
  const char invalid_email1[] = "user";
  const char invalid_email2[] = "user@@what.com";
  EXPECT_EQ(invalid_email1, CanonicalizeEmail(invalid_email1));
  EXPECT_EQ(invalid_email2, CanonicalizeEmail(invalid_email2));
  EXPECT_EQ("user", CanonicalizeEmail("USER"));
}

TEST(EphemeralUtilTest, EmailAddressIgnoreCaps) {
  EXPECT_EQ(CanonicalizeEmail("user@what.com"),
            CanonicalizeEmail("UsEr@what.com"));
}

TEST(EphemeralUtilTest, EmailAddressIgnoreDomainCaps) {
  EXPECT_EQ(CanonicalizeEmail("user@what.com"),
            CanonicalizeEmail("UsEr@what.COM"));
}

TEST(EphemeralUtilTest, EmailAddressRejectOneUsernameDot) {
  EXPECT_NE(CanonicalizeEmail("u.ser@what.com"),
            CanonicalizeEmail("UsEr@what.com"));
}

TEST(EphemeralUtilTest, EmailAddressMatchWithOneUsernameDot) {
  EXPECT_EQ(CanonicalizeEmail("u.ser@what.com"),
            CanonicalizeEmail("U.sEr@what.com"));
}

TEST(EphemeralUtilTest, EmailAddressIgnoreOneUsernameDot) {
  EXPECT_EQ(CanonicalizeEmail("us.er@gmail.com"),
            CanonicalizeEmail("UsEr@gmail.com"));
}

TEST(EphemeralUtilTest, EmailAddressIgnoreOneUsernameDotAndIgnoreCaps) {
  EXPECT_EQ(CanonicalizeEmail("user@gmail.com"),
            CanonicalizeEmail("US.ER@GMAIL.COM"));
}

TEST(EphemeralUtilTest, EmailAddressIgnoreManyUsernameDots) {
  EXPECT_EQ(CanonicalizeEmail("u.ser@gmail.com"),
            CanonicalizeEmail("Us.E.r@gmail.com"));
}

TEST(EphemeralUtilTest, EmailAddressIgnoreConsecutiveUsernameDots) {
  EXPECT_EQ(CanonicalizeEmail("use.r@gmail.com"),
            CanonicalizeEmail("Us....E.r@gmail.com"));
}

TEST(EphemeralUtilTest, EmailAddressDifferentOnesRejected) {
  EXPECT_NE(CanonicalizeEmail("who@what.com"),
            CanonicalizeEmail("Us....E.r@what.com"));
}

TEST(EphemeralUtilTest, GooglemailNotCanonicalizedToGmail) {
  const char googlemail[] = "user@googlemail.com";
  EXPECT_EQ(googlemail, CanonicalizeEmail(googlemail));
}

TEST(EphemeralUtilTest, GenerateDeviceLocalAccountUserId_PUBLIC_SESSION) {
  const char account_id[] = "kiosk_app";
  std::string user = GenerateDeviceLocalAccountUserId(
      account_id, em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_PUBLIC_SESSION);
  EXPECT_EQ("6b696f736b5f617070@public-accounts.device-local.localhost", user);
}

TEST(EphemeralUtilTest, GenerateDeviceLocalAccountUserId_KIOSK_APP) {
  const char account_id[] = "kiosk_app";
  std::string user = GenerateDeviceLocalAccountUserId(
      account_id, em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_KIOSK_APP);
  EXPECT_EQ("6b696f736b5f617070@kiosk-apps.device-local.localhost", user);
}

TEST(EphemeralUtilTest, GenerateDeviceLocalAccountUserId_KIOSK_ANDROID_APP) {
  const char account_id[] = "kiosk_app";
  std::string user = GenerateDeviceLocalAccountUserId(
      account_id,
      em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_KIOSK_ANDROID_APP);
  EXPECT_EQ("6b696f736b5f617070@arc-kiosk-apps.device-local.localhost", user);
}

TEST(EphemeralUtilTest, GenerateDeviceLocalAccountUserId_SAML_PUBLIC_SESSION) {
  const char account_id[] = "kiosk_app";
  std::string user = GenerateDeviceLocalAccountUserId(
      account_id,
      em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_SAML_PUBLIC_SESSION);
  EXPECT_EQ("6b696f736b5f617070@saml-public-accounts.device-local.localhost",
            user);
}

TEST(EphemeralUtilTest, GenerateDeviceLocalAccountUserId_WEB_KIOSK_APP) {
  const char account_id[] = "kiosk_app";
  std::string user = GenerateDeviceLocalAccountUserId(
      account_id, em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_WEB_KIOSK_APP);
  EXPECT_EQ("6b696f736b5f617070@web-kiosk-apps.device-local.localhost", user);
}
}  // namespace policy
