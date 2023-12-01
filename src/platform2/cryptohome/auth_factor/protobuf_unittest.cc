// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/protobuf.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace cryptohome {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Optional;

TEST(AuthFactorTypeToProto, AuthFactorTypeConversionIsInvertable) {
  // Test a round trip of conversion gets back the original types.
  EXPECT_THAT(
      AuthFactorTypeFromProto(AuthFactorTypeToProto(AuthFactorType::kPassword)),
      Eq(AuthFactorType::kPassword));
  EXPECT_THAT(
      AuthFactorTypeFromProto(AuthFactorTypeToProto(AuthFactorType::kPin)),
      Eq(AuthFactorType::kPin));
  EXPECT_THAT(AuthFactorTypeFromProto(
                  AuthFactorTypeToProto(AuthFactorType::kCryptohomeRecovery)),
              Eq(AuthFactorType::kCryptohomeRecovery));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_PIN)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_PIN));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_KIOSK)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_KIOSK));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT));
  EXPECT_THAT(AuthFactorTypeToProto(*AuthFactorTypeFromProto(
                  user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT)),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT));

  // These proto types are known to not be supported
  EXPECT_THAT(
      AuthFactorTypeFromProto(user_data_auth::AUTH_FACTOR_TYPE_UNSPECIFIED),
      Eq(AuthFactorType::kUnspecified));
}

TEST(AuthFactorTypeFromProto,
     AuthFactorTypeConversionFromProtoCoversAllValues) {
  // With proto enums we can't use a "complete" switch to cover every value so
  // we enforce that every value is given an explicit mapping (even if just to
  // Unspecified) via this test.
  for (int raw_type = user_data_auth::AuthFactorType_MIN;
       raw_type <= user_data_auth::AuthFactorType_MAX; ++raw_type) {
    if (!user_data_auth::AuthFactorType_IsValid(raw_type)) {
      continue;
    }
    auto type = static_cast<user_data_auth::AuthFactorType>(raw_type);
    EXPECT_THAT(AuthFactorTypeFromProto(type), Optional(_))
        << "user_data_auth::AuthFactorType has no mapping for "
        << user_data_auth::AuthFactorType_Name(type);
  }
}

}  // namespace
}  // namespace cryptohome
