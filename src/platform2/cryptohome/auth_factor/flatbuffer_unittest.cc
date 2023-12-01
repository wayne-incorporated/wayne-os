// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/flatbuffer.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/flatbuffer_schemas/enumerations.h"

namespace cryptohome {
namespace {

using ::testing::Eq;

TEST(SerializeAuthFactorType, TypeConversionIsInvertable) {
  // Test a round trip of all of the (not-unspecified) values.
  EXPECT_THAT(DeserializeAuthFactorType(
                  *SerializeAuthFactorType(AuthFactorType::kPassword)),
              Eq(AuthFactorType::kPassword));
  EXPECT_THAT(
      DeserializeAuthFactorType(*SerializeAuthFactorType(AuthFactorType::kPin)),
      Eq(AuthFactorType::kPin));
  EXPECT_THAT(DeserializeAuthFactorType(*SerializeAuthFactorType(
                  AuthFactorType::kCryptohomeRecovery)),
              Eq(AuthFactorType::kCryptohomeRecovery));
  EXPECT_THAT(DeserializeAuthFactorType(
                  *SerializeAuthFactorType(AuthFactorType::kKiosk)),
              Eq(AuthFactorType::kKiosk));
  EXPECT_THAT(DeserializeAuthFactorType(
                  *SerializeAuthFactorType(AuthFactorType::kSmartCard)),
              Eq(AuthFactorType::kSmartCard));
  EXPECT_THAT(DeserializeAuthFactorType(
                  *SerializeAuthFactorType(AuthFactorType::kLegacyFingerprint)),
              Eq(AuthFactorType::kLegacyFingerprint));
  EXPECT_THAT(DeserializeAuthFactorType(
                  *SerializeAuthFactorType(AuthFactorType::kFingerprint)),
              Eq(AuthFactorType::kFingerprint));
}

}  // namespace
}  // namespace cryptohome
