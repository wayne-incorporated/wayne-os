// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/pin.h"

#include <limits>
#include <memory>
#include <utility>

#include <base/test/test_future.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "base/time/time.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_factor/types/test_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/mock_le_credential_manager.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::Optional;

class PinDriverTest : public AuthFactorDriverGenericTest {
 protected:
  static constexpr uint64_t kLeLabel = 0xdeadbeefbaadf00d;

  PinDriverTest() {
    auto le_manager = std::make_unique<MockLECredentialManager>();
    le_manager_ = le_manager.get();
    crypto_.set_le_manager_for_testing(std::move(le_manager));
  }

  MockLECredentialManager* le_manager_;
};

TEST_F(PinDriverTest, PinConvertToProto) {
  // Setup
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;
  AuthFactorMetadata metadata =
      CreateMetadataWithType<auth_factor::PinMetadata>();
  metadata.common.lockout_policy = auth_factor::LockoutPolicy::ATTEMPT_LIMITED;

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  ASSERT_THAT(proto, Optional(_));
  EXPECT_THAT(proto.value().type(), Eq(user_data_auth::AUTH_FACTOR_TYPE_PIN));
  EXPECT_THAT(proto.value().label(), Eq(kLabel));
  EXPECT_THAT(proto->common_metadata().chromeos_version_last_updated(),
              Eq(kChromeosVersion));
  EXPECT_THAT(proto->common_metadata().chrome_version_last_updated(),
              Eq(kChromeVersion));
  EXPECT_THAT(proto->common_metadata().lockout_policy(),
              Eq(user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED));
  EXPECT_THAT(proto.value().has_pin_metadata(), IsTrue());
}

TEST_F(PinDriverTest, PinConvertToProtoNullOpt) {
  // Setup
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;
  AuthFactorMetadata metadata;

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  EXPECT_THAT(proto, Eq(std::nullopt));
}

TEST_F(PinDriverTest, UnsupportedWithKiosk) {
  // Setup
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  // Test, Verify.
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kKiosk}),
      IsFalse());
}

TEST_F(PinDriverTest, SupportedWithVk) {
  // Setup
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  // Test, Verify
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset}, {}),
      IsTrue());
}

TEST_F(PinDriverTest, SupportedWithUss) {
  // Setup
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kUserSecretStash}, {}),
              IsTrue());
}

TEST_F(PinDriverTest, UnsupportedByBlock) {
  // Setup
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(false));
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsFalse());
}

TEST_F(PinDriverTest, SupportedByBlock) {
  // Setup
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillOnce(ReturnValue(true));
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsTrue());
}

TEST_F(PinDriverTest, PrepareForAddFails) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PinDriverTest, PrepareForAuthFails) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PinDriverTest, GetDelayFailsWithWrongFactorType) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  AuthFactor factor(AuthFactorType::kPassword, kLabel,
                    CreateMetadataWithType<auth_factor::PasswordMetadata>(),
                    {.state = TpmEccAuthBlockState()});

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PinDriverTest, GetDelayFailsWithoutLeLabel) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  AuthFactor factor(AuthFactorType::kPin, kLabel,
                    CreateMetadataWithType<auth_factor::PinMetadata>(),
                    {.state = PinWeaverAuthBlockState()});

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PinDriverTest, GetDelayInfinite) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  AuthFactor factor(AuthFactorType::kPin, kLabel,
                    CreateMetadataWithType<auth_factor::PinMetadata>(),
                    {.state = PinWeaverAuthBlockState({.le_label = kLeLabel})});
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(std::numeric_limits<uint32_t>::max()));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, IsOk());
  EXPECT_THAT(delay_in_ms->is_max(), IsTrue());
}

TEST_F(PinDriverTest, GetDelayFinite) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  AuthFactor factor(AuthFactorType::kPin, kLabel,
                    CreateMetadataWithType<auth_factor::PinMetadata>(),
                    {.state = PinWeaverAuthBlockState({.le_label = kLeLabel})});
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(10));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, IsOk());
  EXPECT_THAT(*delay_in_ms, Eq(base::Seconds(10)));
}

TEST_F(PinDriverTest, GetDelayZero) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  AuthFactor factor(AuthFactorType::kPin, kLabel,
                    CreateMetadataWithType<auth_factor::PinMetadata>(),
                    {.state = PinWeaverAuthBlockState({.le_label = kLeLabel})});
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(0));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, IsOk());
  EXPECT_THAT(delay_in_ms->is_zero(), IsTrue());
}

TEST_F(PinDriverTest, GetExpirationFails) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  AuthFactor factor(AuthFactorType::kPin, kLabel,
                    CreateMetadataWithType<auth_factor::PinMetadata>(),
                    {.state = PinWeaverAuthBlockState()});

  auto expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(expired, NotOk());
  EXPECT_THAT(expired.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PinDriverTest, CreateCredentialVerifierFails) {
  PinAuthFactorDriver pin_driver(&crypto_);
  AuthFactorDriver& driver = pin_driver;

  auto verifier = driver.CreateCredentialVerifier(kLabel, {});
  EXPECT_THAT(verifier, IsNull());
}

}  // namespace
}  // namespace cryptohome
