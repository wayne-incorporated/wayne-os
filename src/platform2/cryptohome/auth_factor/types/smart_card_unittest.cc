// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/smart_card.h"

#include <utility>

#include <base/test/test_future.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_factor/types/test_utils.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/challenge_credentials/mock_challenge_credentials_helper.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/mock_key_challenge_service.h"
#include "cryptohome/mock_key_challenge_service_factory.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::hwsec_foundation::status::OkStatus;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::Optional;

class SmartCardDriverTest : public AuthFactorDriverGenericTest {
 protected:
  const std::string kPublicKeyStr{"1a2b3c4d5e6f"};
  const brillo::Blob kPublicKey{brillo::BlobFromString(kPublicKeyStr)};
  const std::string kCcDbusServiceName{"cc_service"};

  MockChallengeCredentialsHelper challenge_credentials_helper_;
  MockKeyChallengeServiceFactory key_challenge_service_factory_;
};

TEST_F(SmartCardDriverTest, ConvertToProto) {
  // Setup
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;
  AuthFactorMetadata metadata =
      CreateMetadataWithType<auth_factor::SmartCardMetadata>(
          {.public_key_spki_der = kPublicKey});

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  ASSERT_THAT(proto, Optional(_));
  EXPECT_THAT(proto.value().type(),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
  EXPECT_THAT(proto.value().label(), Eq(kLabel));
  EXPECT_THAT(proto->common_metadata().chromeos_version_last_updated(),
              Eq(kChromeosVersion));
  EXPECT_THAT(proto->common_metadata().chrome_version_last_updated(),
              Eq(kChromeVersion));
  EXPECT_THAT(proto->common_metadata().lockout_policy(),
              Eq(user_data_auth::LOCKOUT_POLICY_NONE));
  EXPECT_THAT(proto.value().has_smart_card_metadata(), IsTrue());
  EXPECT_THAT(proto.value().smart_card_metadata().public_key_spki_der(),
              Eq(kPublicKeyStr));
}

TEST_F(SmartCardDriverTest, ConvertToProtoNullOpt) {
  // Setup
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;
  AuthFactorMetadata metadata;

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  EXPECT_THAT(proto, Eq(std::nullopt));
}

TEST_F(SmartCardDriverTest, UnsupportedWithKiosk) {
  // Setup
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  // Test, Verify.
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kKiosk}),
      IsFalse());
}

TEST_F(SmartCardDriverTest, SupportedWithVk) {
  // Setup
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  // Test, Verify
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset}, {}),
      IsTrue());
}

TEST_F(SmartCardDriverTest, SupportedWithUss) {
  // Setup
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kUserSecretStash}, {}),
              IsTrue());
}

TEST_F(SmartCardDriverTest, UnsupportedByBlock) {
  // Setup
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(false));
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsFalse());
}

TEST_F(SmartCardDriverTest, SupportedByBlock) {
  // Setup
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsTrue());
}

TEST_F(SmartCardDriverTest, PrepareForAddFails) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(SmartCardDriverTest, PrepareForAuthFails) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(SmartCardDriverTest, GetDelayFails) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  AuthFactor factor(AuthFactorType::kSmartCard, kLabel,
                    CreateMetadataWithType<auth_factor::SmartCardMetadata>(
                        {.public_key_spki_der = kPublicKey}),
                    {.state = ChallengeCredentialAuthBlockState()});

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(SmartCardDriverTest, GetExpirationFails) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  AuthFactor factor(AuthFactorType::kSmartCard, kLabel,
                    CreateMetadataWithType<auth_factor::SmartCardMetadata>(
                        {.public_key_spki_der = kPublicKey}),
                    {.state = ChallengeCredentialAuthBlockState()});

  auto expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(expired, NotOk());
  EXPECT_THAT(expired.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(SmartCardDriverTest, CreateCredentialVerifierFailsWithoutDbus) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  ChallengeCredentialAuthInput cc_input = {
      .public_key_spki_der = kPublicKey,
      .challenge_signature_algorithms =
          {structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1},
  };
  AuthInput auth_input = {.username = kUser,
                          .challenge_credential_auth_input = cc_input};
  auto verifier = driver.CreateCredentialVerifier(kLabel, auth_input);
  EXPECT_THAT(verifier, IsNull());
}

TEST_F(SmartCardDriverTest, CreateCredentialVerifierFailsWithoutHelper) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_, AsyncInitPtr<ChallengeCredentialsHelper>(nullptr),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  ChallengeCredentialAuthInput cc_input = {
      .public_key_spki_der = kPublicKey,
      .challenge_signature_algorithms =
          {structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1},
      .dbus_service_name = kCcDbusServiceName};
  AuthInput auth_input = {.username = kUser,
                          .challenge_credential_auth_input = cc_input};
  auto verifier = driver.CreateCredentialVerifier(kLabel, auth_input);
  EXPECT_THAT(verifier, IsNull());
}

TEST_F(SmartCardDriverTest, CreateCredentialVerifier) {
  SmartCardAuthFactorDriver sc_driver(
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_);
  AuthFactorDriver& driver = sc_driver;

  ChallengeCredentialAuthInput cc_input = {
      .public_key_spki_der = kPublicKey,
      .challenge_signature_algorithms =
          {structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1},
      .dbus_service_name = kCcDbusServiceName};
  AuthInput auth_input = {.username = kUser,
                          .challenge_credential_auth_input = cc_input};
  EXPECT_CALL(key_challenge_service_factory_, New(kCcDbusServiceName))
      .WillOnce([](const std::string&) {
        return std::make_unique<MockKeyChallengeService>();
      });
  auto verifier = driver.CreateCredentialVerifier(kLabel, auth_input);
  ASSERT_THAT(verifier, NotNull());
  EXPECT_THAT(verifier->auth_factor_type(), Eq(AuthFactorType::kSmartCard));
  EXPECT_THAT(verifier->auth_factor_label(), Eq(kLabel));

  EXPECT_CALL(challenge_credentials_helper_,
              VerifyKey(auth_input.username, _, _, _))
      .WillOnce([this](const Username&,
                       const structure::ChallengePublicKeyInfo& public_key_info,
                       std::unique_ptr<KeyChallengeService>,
                       ChallengeCredentialsHelper::VerifyKeyCallback callback) {
        EXPECT_THAT(public_key_info.public_key_spki_der, Eq(kPublicKey));
        EXPECT_THAT(
            public_key_info.signature_algorithm,
            ElementsAre(
                structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1));
        std::move(callback).Run(OkStatus<error::CryptohomeCryptoError>());
      });
  TestFuture<CryptohomeStatus> good_result;
  verifier->Verify(auth_input, good_result.GetCallback());
  EXPECT_THAT(good_result.Get(), IsOk());
}

}  // namespace
}  // namespace cryptohome
