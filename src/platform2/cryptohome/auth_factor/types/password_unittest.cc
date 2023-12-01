// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/password.h"

#include <base/test/test_future.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_factor/types/test_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::testing::_;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::Optional;

class PasswordDriverTest : public AuthFactorDriverGenericTest {
 protected:
  const brillo::SecureBlob kPassword{"the password"};
  const brillo::SecureBlob kWrongPassword{"not the password"};
};

TEST_F(PasswordDriverTest, PasswordConvertToProto) {
  // Setup
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;
  AuthFactorMetadata metadata =
      CreateMetadataWithType<auth_factor::PasswordMetadata>();

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  ASSERT_THAT(proto, Optional(_));
  EXPECT_THAT(proto->common_metadata().chromeos_version_last_updated(),
              Eq(kChromeosVersion));
  EXPECT_THAT(proto->common_metadata().chrome_version_last_updated(),
              Eq(kChromeVersion));
  EXPECT_THAT(proto->common_metadata().lockout_policy(),
              Eq(user_data_auth::LOCKOUT_POLICY_NONE));
  EXPECT_THAT(proto.value().type(),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD));
  EXPECT_THAT(proto.value().label(), Eq(kLabel));
  EXPECT_THAT(proto.value().has_password_metadata(), IsTrue());
}

TEST_F(PasswordDriverTest, PasswordConvertToProtoErrorNoMetadata) {
  // Setup
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;
  AuthFactorMetadata metadata;

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  EXPECT_THAT(proto, Eq(std::nullopt));
}

TEST_F(PasswordDriverTest, SupportedWithoutKiosk) {
  // Setup
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  // Test, Verify
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset}, {}),
      IsTrue());
  EXPECT_THAT(driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset},
                                          {AuthFactorType::kPin}),
              IsTrue());
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kVaultKeyset},
                  {AuthFactorType::kPassword, AuthFactorType::kPin}),
              IsTrue());
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kUserSecretStash}, {}),
              IsTrue());
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kPin}),
      IsTrue());
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kUserSecretStash},
                  {AuthFactorType::kPassword, AuthFactorType::kPin}),
              IsTrue());
}

TEST_F(PasswordDriverTest, UnsupportedWithKiosk) {
  // Setup
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset},
                                          {AuthFactorType::kKiosk}),
              IsFalse());
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kKiosk}),
      IsFalse());
}

TEST_F(PasswordDriverTest, AlwaysSupportedByHardware) {
  // Setup
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsTrue());
}

TEST_F(PasswordDriverTest, GetDelayFails) {
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  AuthFactor factor(AuthFactorType::kPassword, kLabel,
                    CreateMetadataWithType<auth_factor::PasswordMetadata>(),
                    {.state = TpmEccAuthBlockState()});

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PasswordDriverTest, GetExpirationFails) {
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  AuthFactor factor(AuthFactorType::kPassword, kLabel,
                    CreateMetadataWithType<auth_factor::PasswordMetadata>(),
                    {.state = TpmEccAuthBlockState()});

  auto expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(expired, NotOk());
  EXPECT_THAT(expired.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PasswordDriverTest, PrepareForAddFails) {
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PasswordDriverTest, PrepareForAuthFails) {
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(PasswordDriverTest, CreateCredentialVerifier) {
  PasswordAuthFactorDriver password_driver;
  AuthFactorDriver& driver = password_driver;

  AuthInput auth_input = {.user_input = kPassword};
  auto verifier = driver.CreateCredentialVerifier(kLabel, auth_input);
  ASSERT_THAT(verifier, NotNull());
  EXPECT_THAT(verifier->auth_factor_type(), Eq(AuthFactorType::kPassword));
  EXPECT_THAT(verifier->auth_factor_label(), Eq(kLabel));

  TestFuture<CryptohomeStatus> good_result;
  verifier->Verify(auth_input, good_result.GetCallback());
  EXPECT_THAT(good_result.Get(), IsOk());
  auth_input.user_input = kWrongPassword;
  TestFuture<CryptohomeStatus> bad_result;
  verifier->Verify(auth_input, bad_result.GetCallback());
  EXPECT_THAT(bad_result.Get(), NotOk());
}

}  // namespace
}  // namespace cryptohome
