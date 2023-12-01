// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/with_driver.h"

#include <memory>
#include <utility>

#include <base/functional/callback.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_blocks/mock_biometrics_command_processor.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/crypto.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_fingerprint_manager.h"
#include "cryptohome/mock_le_credential_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/user_secret_stash/mock_user_metadata.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {
namespace {

using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::IsEmpty;
using ::testing::Return;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

class AuthFactorWithDriverTest : public ::testing::Test {
 protected:
  // Useful generic constants to use for usernames.
  const Username kUser{"user"};
  const ObfuscatedUsername kObfuscatedUser{
      brillo::cryptohome::home::SanitizeUserName(kUser)};

  // Useful generic constants to use for labels and version metadata.
  static constexpr char kLabel[] = "some-label";
  static constexpr char kChromeosVersion[] = "1.2.3_a_b_c";
  static constexpr char kChromeVersion[] = "1.2.3.4";
  static constexpr uint64_t kLeLabel = 0xdeadbeefbaadf00d;

  // Create a factor with the given factor type and metadata and auth block
  // state types.
  template <typename MetadataType, typename AuthBlockStateType>
  static AuthFactor CreateFactor(AuthFactorType type,
                                 MetadataType type_metadata,
                                 AuthBlockStateType type_state) {
    AuthFactorMetadata metadata = {
        .common = {.chromeos_version_last_updated = kChromeosVersion,
                   .chrome_version_last_updated = kChromeVersion},
        .metadata = std::move(type_metadata),
    };
    AuthBlockState state = {.state = std::move(type_state)};
    return AuthFactor(type, kLabel, std::move(metadata), std::move(state));
  }

  AuthFactorWithDriverTest() {
    auto le_manager = std::make_unique<MockLECredentialManager>();
    le_manager_ = le_manager.get();
    crypto_.set_le_manager_for_testing(std::move(le_manager));

    auto processor = std::make_unique<MockBiometricsCommandProcessor>();
    bio_command_processor_ = processor.get();
    EXPECT_CALL(*bio_command_processor_, SetEnrollScanDoneCallback(_));
    EXPECT_CALL(*bio_command_processor_, SetAuthScanDoneCallback(_));
    EXPECT_CALL(*bio_command_processor_, SetSessionFailedCallback(_));
    bio_service_ = std::make_unique<BiometricsAuthBlockService>(
        std::move(processor), /*enroll_signal_sender=*/base::DoNothing(),
        /*auth_signal_sender=*/base::DoNothing());
  }

  // Mocks for all of the manager dependencies.
  MockPlatform platform_;
  hwsec::MockCryptohomeFrontend hwsec_;
  hwsec::MockPinWeaverFrontend pinweaver_;
  MockCryptohomeKeysManager cryptohome_keys_manager_;
  Crypto crypto_{&hwsec_, &pinweaver_, &cryptohome_keys_manager_,
                 /*recovery_hwsec=*/nullptr};
  MockLECredentialManager* le_manager_;
  MockFingerprintManager fp_manager_;
  FingerprintAuthBlockService fp_service_{
      AsyncInitPtr<FingerprintManager>(&fp_manager_), base::DoNothing()};
  MockBiometricsCommandProcessor* bio_command_processor_;
  std::unique_ptr<BiometricsAuthBlockService> bio_service_;
  MockUserMetadataReader mock_user_metadata_reader_;

  // A real version of the manager, using mock inputs.
  AuthFactorDriverManager manager_{
      &platform_,
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(nullptr),
      nullptr,
      &fp_service_,
      AsyncInitPtr<BiometricsAuthBlockService>(base::BindRepeating(
          [](AuthFactorWithDriverTest* test) {
            return test->bio_service_.get();
          },
          base::Unretained(this))),
      &mock_user_metadata_reader_};
};

TEST_F(AuthFactorWithDriverTest, PasswordSupportsAllIntents) {
  AuthFactor password_factor =
      CreateFactor(AuthFactorType::kPassword, auth_factor::PasswordMetadata(),
                   TpmEccAuthBlockState());

  auto intents =
      GetSupportedIntents(kObfuscatedUser, password_factor, manager_);

  EXPECT_THAT(intents, UnorderedElementsAreArray(kAllAuthIntents));
}

TEST_F(AuthFactorWithDriverTest, PinNoIntentsWithNoHardware) {
  AuthFactor pin_factor =
      CreateFactor(AuthFactorType::kPin, auth_factor::PinMetadata(),
                   PinWeaverAuthBlockState{.le_label = kLeLabel});
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(false));

  auto intents = GetSupportedIntents(kObfuscatedUser, pin_factor, manager_);

  EXPECT_THAT(intents, IsEmpty());
}

TEST_F(AuthFactorWithDriverTest, PinNoIntentsWithDelay) {
  AuthFactor pin_factor =
      CreateFactor(AuthFactorType::kPin, auth_factor::PinMetadata(),
                   PinWeaverAuthBlockState{.le_label = kLeLabel});
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillOnce(ReturnValue(true));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(15));

  auto intents = GetSupportedIntents(kObfuscatedUser, pin_factor, manager_);

  EXPECT_THAT(intents, IsEmpty());
}

TEST_F(AuthFactorWithDriverTest, PinSupportAllIntentsWhenUnlocked) {
  AuthFactor pin_factor =
      CreateFactor(AuthFactorType::kPin, auth_factor::PinMetadata(),
                   PinWeaverAuthBlockState{.le_label = kLeLabel});
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillOnce(ReturnValue(true));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(0));

  auto intents = GetSupportedIntents(kObfuscatedUser, pin_factor, manager_);

  EXPECT_THAT(intents, UnorderedElementsAreArray(kAllAuthIntents));
}

TEST_F(AuthFactorWithDriverTest, FingerprintNoIntentsWithNoHardware) {
  AuthFactor fp_factor = CreateFactor(AuthFactorType::kFingerprint,
                                      auth_factor::FingerprintMetadata(),
                                      FingerprintAuthBlockState{});
  EXPECT_CALL(*bio_command_processor_, IsReady()).WillOnce(Return(false));

  auto intents = GetSupportedIntents(kObfuscatedUser, fp_factor, manager_);

  EXPECT_THAT(intents, IsEmpty());
}

TEST_F(AuthFactorWithDriverTest, FingerprintNoIntentsWhenExpired) {
  AuthFactor fp_factor = CreateFactor(AuthFactorType::kFingerprint,
                                      auth_factor::FingerprintMetadata(),
                                      FingerprintAuthBlockState{});
  EXPECT_CALL(*bio_command_processor_, IsReady()).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsBiometricsPinWeaverEnabled())
      .WillOnce(ReturnValue(true));
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillOnce(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetExpirationInSeconds(kLeLabel))
      .WillOnce(ReturnValue(0));

  auto intents = GetSupportedIntents(kObfuscatedUser, fp_factor, manager_);

  EXPECT_THAT(intents, IsEmpty());
}

TEST_F(AuthFactorWithDriverTest, FingerprintNoIntentsWithDelay) {
  AuthFactor fp_factor = CreateFactor(AuthFactorType::kFingerprint,
                                      auth_factor::FingerprintMetadata(),
                                      FingerprintAuthBlockState{});
  EXPECT_CALL(*bio_command_processor_, IsReady()).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsBiometricsPinWeaverEnabled())
      .WillOnce(ReturnValue(true));
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillRepeatedly(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetExpirationInSeconds(kLeLabel))
      .WillOnce(ReturnValue(15));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(15));

  auto intents = GetSupportedIntents(kObfuscatedUser, fp_factor, manager_);

  EXPECT_THAT(intents, IsEmpty());
}

TEST_F(AuthFactorWithDriverTest, FingerprintSupportsSomeIntents) {
  AuthFactor fp_factor = CreateFactor(AuthFactorType::kFingerprint,
                                      auth_factor::FingerprintMetadata(),
                                      FingerprintAuthBlockState{});
  EXPECT_CALL(*bio_command_processor_, IsReady()).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsBiometricsPinWeaverEnabled())
      .WillOnce(ReturnValue(true));
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillRepeatedly(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetExpirationInSeconds(kLeLabel))
      .WillOnce(ReturnValue(15));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(0));

  auto intents = GetSupportedIntents(kObfuscatedUser, fp_factor, manager_);

  EXPECT_THAT(intents, UnorderedElementsAre(AuthIntent::kVerifyOnly,
                                            AuthIntent::kWebAuthn));
}

}  // namespace
}  // namespace cryptohome
