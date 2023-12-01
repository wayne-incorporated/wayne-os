// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/kiosk.h"

#include <base/test/test_future.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_factor/types/test_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::hwsec_foundation::error::testing::NotOk;
using ::testing::_;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::Optional;

class KioskDriverTest : public AuthFactorDriverGenericTest {};

TEST_F(KioskDriverTest, KioskConvertToProto) {
  // Setup
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;
  AuthFactorMetadata metadata =
      CreateMetadataWithType<auth_factor::KioskMetadata>();

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  ASSERT_THAT(proto, Optional(_));
  EXPECT_THAT(proto.value().type(), Eq(user_data_auth::AUTH_FACTOR_TYPE_KIOSK));
  EXPECT_THAT(proto.value().label(), Eq(kLabel));
  EXPECT_THAT(proto->common_metadata().chromeos_version_last_updated(),
              Eq(kChromeosVersion));
  EXPECT_THAT(proto->common_metadata().chrome_version_last_updated(),
              Eq(kChromeVersion));
  EXPECT_THAT(proto->common_metadata().lockout_policy(),
              Eq(user_data_auth::LOCKOUT_POLICY_NONE));
  EXPECT_THAT(proto.value().has_kiosk_metadata(), IsTrue());
}

TEST_F(KioskDriverTest, KioskConvertToProtoNullOpt) {
  // Setup
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;
  AuthFactorMetadata metadata;

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  EXPECT_THAT(proto, Eq(std::nullopt));
}

TEST_F(KioskDriverTest, SupportedWithNoOtherFactors) {
  // Setup
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  // Test, Verify
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset}, {}),
      IsTrue());
  EXPECT_THAT(driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset},
                                          {AuthFactorType::kKiosk}),
              IsTrue());
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kUserSecretStash}, {}),
              IsTrue());
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kKiosk}),
      IsTrue());
}

TEST_F(KioskDriverTest, UnsupportedWithOtherFactors) {
  // Setup
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset},
                                          {AuthFactorType::kPassword}),
              IsFalse());
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kPassword}),
      IsFalse());
}

TEST_F(KioskDriverTest, AlwaysSupportedByHardare) {
  // Setup
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsTrue());
}

TEST_F(KioskDriverTest, PrepareForAddFails) {
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(KioskDriverTest, PrepareForAuthFails) {
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(KioskDriverTest, GetDelayFails) {
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  AuthFactor factor(AuthFactorType::kKiosk, kLabel,
                    CreateMetadataWithType<auth_factor::KioskMetadata>(),
                    {.state = TpmEccAuthBlockState()});

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(KioskDriverTest, GetExpirationFails) {
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  AuthFactor factor(AuthFactorType::kKiosk, kLabel,
                    CreateMetadataWithType<auth_factor::KioskMetadata>(),
                    {.state = TpmEccAuthBlockState()});

  auto expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(expired, NotOk());
  EXPECT_THAT(expired.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(KioskDriverTest, CreateCredentialVerifierFails) {
  KioskAuthFactorDriver kiosk_driver;
  AuthFactorDriver& driver = kiosk_driver;

  auto verifier = driver.CreateCredentialVerifier(kLabel, {});
  EXPECT_THAT(verifier, IsNull());
}

}  // namespace
}  // namespace cryptohome
