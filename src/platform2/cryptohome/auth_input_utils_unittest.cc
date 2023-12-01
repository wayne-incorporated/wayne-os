// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_input_utils.h"

#include <optional>

#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/crypto.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/mock_platform.h"

using brillo::SecureBlob;

namespace cryptohome {

class AuthInputUtilsPlatformTest : public ::testing::Test {
 protected:
  const Username kUserName{"someusername"};
  const ObfuscatedUsername kObfuscatedUsername{"fake-user@example.org"};

  testing::NiceMock<MockPlatform> platform_;
};

// Test the conversion from the password AuthInput proto into the cryptohome
// struct.
TEST_F(AuthInputUtilsPlatformTest, CreateAuthInputPassword) {
  constexpr char kPassword[] = "fake-password";

  user_data_auth::AuthInput proto;
  proto.mutable_password_input()->set_secret(kPassword);

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform_, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/false,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  ASSERT_TRUE(auth_input.has_value());
  EXPECT_EQ(auth_input.value().user_input, SecureBlob(kPassword));
  EXPECT_EQ(auth_input.value().obfuscated_username, kObfuscatedUsername);
  EXPECT_EQ(auth_input.value().locked_to_single_user, false);
}

// Test the conversion from the password AuthInput proto into the cryptohome
// struct, with the locked_to_single_user flag set.
TEST_F(AuthInputUtilsPlatformTest, CreateAuthInputPasswordLocked) {
  constexpr char kPassword[] = "fake-password";

  user_data_auth::AuthInput proto;
  proto.mutable_password_input()->set_secret(kPassword);

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform_, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/true,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  ASSERT_TRUE(auth_input.has_value());
  EXPECT_EQ(auth_input.value().user_input, SecureBlob(kPassword));
  EXPECT_EQ(auth_input.value().obfuscated_username, kObfuscatedUsername);
  EXPECT_EQ(auth_input.value().locked_to_single_user, true);
}

// Test the conversion from the smart card AuthInput proto into the cryptohome
// struct, with the public_key_spki_der from auth_factor_metadata set.
TEST_F(AuthInputUtilsPlatformTest, CreateAuthInputSmartCard) {
  constexpr char kPublicKeySPKIDer[] = "public_key";

  user_data_auth::AuthInput proto;
  proto.mutable_smart_card_input()->add_signature_algorithms(
      user_data_auth::CHALLENGE_RSASSA_PKCS1_V1_5_SHA1);

  brillo::Blob public_key_spki_der = brillo::BlobFromString(kPublicKeySPKIDer);
  AuthFactorMetadata auth_factor_metadata{
      .metadata = auth_factor::SmartCardMetadata{.public_key_spki_der =
                                                     public_key_spki_der},
  };
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform_, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/false,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  ASSERT_TRUE(auth_input.has_value());
  EXPECT_EQ(auth_input.value().obfuscated_username, kObfuscatedUsername);
  EXPECT_EQ(auth_input.value().locked_to_single_user, false);
  EXPECT_TRUE(auth_input.value().challenge_credential_auth_input.has_value());
  EXPECT_EQ(auth_input.value()
                .challenge_credential_auth_input.value()
                .public_key_spki_der,
            public_key_spki_der);
}

// Test the conversion from an empty AuthInput proto fails.
TEST_F(AuthInputUtilsPlatformTest, CreateAuthInputErrorEmpty) {
  user_data_auth::AuthInput proto;

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform_, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/false,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  EXPECT_FALSE(auth_input.has_value());
}

TEST_F(AuthInputUtilsPlatformTest, CreateAuthInputRecoveryCreate) {
  constexpr char kMediatorPubKey[] = "fake_mediator_pub_key";

  user_data_auth::AuthInput proto;
  proto.mutable_cryptohome_recovery_input()->set_mediator_pub_key(
      kMediatorPubKey);

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform_, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/true,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  ASSERT_TRUE(auth_input.has_value());
  ASSERT_TRUE(auth_input.value().cryptohome_recovery_auth_input.has_value());
  EXPECT_EQ(auth_input.value()
                .cryptohome_recovery_auth_input.value()
                .mediator_pub_key,
            SecureBlob(kMediatorPubKey));
}

TEST_F(AuthInputUtilsPlatformTest, CreateAuthInputRecoveryDerive) {
  constexpr char kEpochResponse[] = "fake_epoch_response";
  constexpr char kResponsePayload[] = "fake_recovery_response";
  SecureBlob ephemeral_pub_key = SecureBlob("fake_ephemeral_pub_key");

  user_data_auth::AuthInput proto;
  proto.mutable_cryptohome_recovery_input()->set_epoch_response(kEpochResponse);
  proto.mutable_cryptohome_recovery_input()->set_recovery_response(
      kResponsePayload);

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input = CreateAuthInput(
      &platform_, proto, kUserName, kObfuscatedUsername,
      /*locked_to_single_user=*/true, ephemeral_pub_key, auth_factor_metadata);
  ASSERT_TRUE(auth_input.has_value());
  ASSERT_TRUE(auth_input.value().cryptohome_recovery_auth_input.has_value());
  EXPECT_EQ(
      auth_input.value().cryptohome_recovery_auth_input.value().epoch_response,
      SecureBlob(kEpochResponse));
  EXPECT_EQ(auth_input.value()
                .cryptohome_recovery_auth_input.value()
                .recovery_response,
            SecureBlob(kResponsePayload));
  EXPECT_EQ(auth_input.value()
                .cryptohome_recovery_auth_input.value()
                .ephemeral_pub_key,
            ephemeral_pub_key);
}

TEST_F(AuthInputUtilsPlatformTest, FromKioskAuthInput) {
  // SETUP
  testing::NiceMock<MockPlatform> platform;
  // Generate a valid passkey from the users id and public salt.
  brillo::SecureBlob public_mount_salt;
  // Mock platform takes care of creating the salt file if needed.
  GetPublicMountSalt(&platform, &public_mount_salt);
  brillo::SecureBlob passkey;
  Crypto::PasswordToPasskey(kUserName->c_str(), public_mount_salt, &passkey);
  user_data_auth::AuthInput proto;
  proto.mutable_kiosk_input();

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/true,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  ASSERT_TRUE(auth_input.has_value());

  // TEST
  EXPECT_EQ(auth_input->user_input, passkey);
}

TEST_F(AuthInputUtilsPlatformTest, FromKioskAuthInputFail) {
  // SETUP
  EXPECT_CALL(platform_,
              WriteSecureBlobToFileAtomicDurable(PublicMountSaltFile(), _, _))
      .WillOnce(Return(false));
  user_data_auth::AuthInput proto;
  proto.mutable_kiosk_input();

  AuthFactorMetadata auth_factor_metadata;
  std::optional<AuthInput> auth_input =
      CreateAuthInput(&platform_, proto, kUserName, kObfuscatedUsername,
                      /*locked_to_single_user=*/true,
                      /*cryptohome_recovery_ephemeral_pub_key=*/std::nullopt,
                      auth_factor_metadata);
  ASSERT_FALSE(auth_input.has_value());
}

TEST(AuthInputUtilsTest, DetermineFactorTypePassword) {
  user_data_auth::AuthInput auth_input;
  auth_input.mutable_password_input();
  EXPECT_EQ(DetermineFactorTypeFromAuthInput(auth_input),
            AuthFactorType::kPassword);
}

TEST(AuthInputUtilsTest, DetermineFactorTypePin) {
  user_data_auth::AuthInput auth_input;
  auth_input.mutable_pin_input();
  EXPECT_EQ(DetermineFactorTypeFromAuthInput(auth_input), AuthFactorType::kPin);
}

TEST(AuthInputUtilsTest, DetermineFactorTypeRecovery) {
  user_data_auth::AuthInput auth_input;
  auth_input.mutable_cryptohome_recovery_input();
  EXPECT_EQ(DetermineFactorTypeFromAuthInput(auth_input),
            AuthFactorType::kCryptohomeRecovery);
}

TEST(AuthInputUtilsTest, DetermineFactorTypeKiosk) {
  user_data_auth::AuthInput auth_input;
  auth_input.mutable_kiosk_input();
  EXPECT_EQ(DetermineFactorTypeFromAuthInput(auth_input),
            AuthFactorType::kKiosk);
}

TEST(AuthInputUtilsTest, DetermineFactorTypeSmartCard) {
  user_data_auth::AuthInput auth_input;
  auth_input.mutable_smart_card_input();
  EXPECT_EQ(DetermineFactorTypeFromAuthInput(auth_input),
            AuthFactorType::kSmartCard);
}

TEST(AuthInputUtilsTest, DetermineFactorTypeErrorUnset) {
  user_data_auth::AuthInput auth_input;
  EXPECT_EQ(DetermineFactorTypeFromAuthInput(auth_input), std::nullopt);
}

}  // namespace cryptohome
