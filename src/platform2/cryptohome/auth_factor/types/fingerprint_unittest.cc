// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/fingerprint.h"

#include <limits>
#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/test/test_future.h>
#include <base/functional/callback.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/biometrics_auth_block_service.h"
#include "cryptohome/auth_blocks/mock_biometrics_command_processor.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_factor/types/test_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/mock_le_credential_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/user_secret_stash/mock_user_metadata.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::Optional;
using ::testing::Return;

class FingerprintDriverTest : public AuthFactorDriverGenericTest {
 protected:
  const error::CryptohomeError::ErrorLocationPair kErrorLocationPlaceholder =
      error::CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          "Testing1");
  static constexpr uint64_t kLeLabel = 0xdeadbeefbaadf00d;

  FingerprintDriverTest() {
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

  MockPlatform platform_;
  MockLECredentialManager* le_manager_;
  MockBiometricsCommandProcessor* bio_command_processor_;
  std::unique_ptr<BiometricsAuthBlockService> bio_service_;
  MockUserMetadataReader mock_user_metadata_reader_;
};

TEST_F(FingerprintDriverTest, ConvertToProto) {
  // Setup
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;
  AuthFactorMetadata metadata =
      CreateMetadataWithType<auth_factor::FingerprintMetadata>();

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  ASSERT_THAT(proto, Optional(_));
  EXPECT_THAT(proto.value().type(),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT));
  EXPECT_THAT(proto.value().label(), Eq(kLabel));
  EXPECT_THAT(proto->common_metadata().chromeos_version_last_updated(),
              Eq(kChromeosVersion));
  EXPECT_THAT(proto->common_metadata().chrome_version_last_updated(),
              Eq(kChromeVersion));
  EXPECT_THAT(proto->common_metadata().lockout_policy(),
              Eq(user_data_auth::LOCKOUT_POLICY_NONE));
  EXPECT_THAT(proto.value().has_fingerprint_metadata(), IsTrue());
}

TEST_F(FingerprintDriverTest, ConvertToProtoNullOpt) {
  // Setup
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;
  AuthFactorMetadata metadata;

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  EXPECT_THAT(proto, Eq(std::nullopt));
}

TEST_F(FingerprintDriverTest, UnsupportedWithVk) {
  // Setup
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  // Test, Verify.
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset}, {}),
      IsFalse());
}

TEST_F(FingerprintDriverTest, SupportedWithVkUssMix) {
  // Setup
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  // Test, Verify.
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset,
                                   AuthFactorStorageType::kUserSecretStash},
                                  {}),
      IsTrue());
}

TEST_F(FingerprintDriverTest, UnsupportedWithKiosk) {
  // Setup
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_, AsyncInitPtr<BiometricsAuthBlockService>(nullptr),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  // Test, Verify.
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kUserSecretStash},
                                  {AuthFactorType::kKiosk}),
      IsFalse());
}

TEST_F(FingerprintDriverTest, UnsupportedByBlock) {
  // Setup
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_, AsyncInitPtr<BiometricsAuthBlockService>(nullptr),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsFalse());
}

TEST_F(FingerprintDriverTest, SupportedByBlock) {
  // Setup
  EXPECT_CALL(*bio_command_processor_, IsReady()).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsReady()).WillOnce(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsBiometricsPinWeaverEnabled())
      .WillOnce(ReturnValue(true));
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  // Test, Verify
  EXPECT_THAT(driver.IsSupportedByHardware(), IsTrue());
}

TEST_F(FingerprintDriverTest, PrepareForAddFailure) {
  // Setup.
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;
  EXPECT_CALL(*bio_command_processor_, StartEnrollSession(_))
      .WillOnce([](auto&& callback) { std::move(callback).Run(false); });

  // Test.
  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());

  // Verify.
  EXPECT_THAT(prepare_result.Get(), NotOk());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
}

TEST_F(FingerprintDriverTest, PrepareForAddSuccess) {
  // Setup.
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;
  EXPECT_CALL(*bio_command_processor_, StartEnrollSession(_))
      .WillOnce([](auto&& callback) { std::move(callback).Run(true); });

  // Test.
  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());

  // Verify.
  EXPECT_THAT(prepare_result.Get(), IsOk());
}

TEST_F(FingerprintDriverTest, PrepareForAuthFailure) {
  // Setup.
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;
  EXPECT_CALL(*bio_command_processor_,
              StartAuthenticateSession(kObfuscatedUser, _))
      .WillOnce(
          [](auto&&, auto&& callback) { std::move(callback).Run(false); });

  // Test.
  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());

  // Verify.
  EXPECT_THAT(prepare_result.Get(), NotOk());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
}

TEST_F(FingerprintDriverTest, PrepareForAuthSuccess) {
  // Setup.
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;
  EXPECT_CALL(*bio_command_processor_,
              StartAuthenticateSession(kObfuscatedUser, _))
      .WillOnce([](auto&&, auto&& callback) { std::move(callback).Run(true); });

  // Test.
  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());

  // Verify.
  EXPECT_THAT(prepare_result.Get(), IsOk());
}

TEST_F(FingerprintDriverTest, GetDelayFailsWithoutLeLabel) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});

  EXPECT_CALL(mock_user_metadata_reader_, Load)
      .WillOnce(ReturnError<CryptohomeError>(
          kErrorLocationPlaceholder, ErrorActionSet(),
          user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE));
}

TEST_F(FingerprintDriverTest, GetDelayInfinite) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillOnce(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(std::numeric_limits<uint32_t>::max()));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, IsOk());
  EXPECT_THAT(delay_in_ms->is_max(), IsTrue());
}

TEST_F(FingerprintDriverTest, GetDelayFinite) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillOnce(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(10));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, IsOk());
  EXPECT_THAT(*delay_in_ms, Eq(base::Seconds(10)));
}

TEST_F(FingerprintDriverTest, GetDelayZero) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillOnce(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetDelayInSeconds(kLeLabel))
      .WillOnce(ReturnValue(0));

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, IsOk());
  EXPECT_THAT(delay_in_ms->is_zero(), IsTrue());
}

TEST_F(FingerprintDriverTest, IsExpiredFailsWithoutLeLabel) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});

  EXPECT_CALL(mock_user_metadata_reader_, Load)
      .WillOnce(ReturnError<CryptohomeError>(
          kErrorLocationPlaceholder, ErrorActionSet(),
          user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE));

  auto is_expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(is_expired, NotOk());
  EXPECT_THAT(is_expired.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE));
}

TEST_F(FingerprintDriverTest, IsNotExpired) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillOnce(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetExpirationInSeconds(kLeLabel))
      .WillOnce(ReturnValue(10));

  auto is_expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(is_expired, IsOk());
  EXPECT_FALSE(*is_expired);
}

TEST_F(FingerprintDriverTest, IsExpired) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  AuthFactor factor(AuthFactorType::kFingerprint, kLabel,
                    CreateMetadataWithType<auth_factor::FingerprintMetadata>(),
                    {.state = FingerprintAuthBlockState()});
  EXPECT_CALL(mock_user_metadata_reader_, Load(kObfuscatedUser))
      .WillOnce(
          ReturnValue(UserMetadata{.fingerprint_rate_limiter_id = kLeLabel}));
  EXPECT_CALL(*le_manager_, GetExpirationInSeconds(kLeLabel))
      .WillOnce(ReturnValue(0));

  auto is_expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(is_expired, IsOk());
  EXPECT_TRUE(*is_expired);
}

TEST_F(FingerprintDriverTest, CreateCredentialVerifierFails) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  auto verifier = driver.CreateCredentialVerifier(kLabel, {});
  EXPECT_THAT(verifier, IsNull());
}

// Verify that the decrypt flag file works correct. When this feature is removed
// this test should be removed along with the flag file mocks in
// manager_unittest.cc.
TEST_F(FingerprintDriverTest, IsFullAuthDecryptUsesFlagFile) {
  FingerprintAuthFactorDriver fp_driver(
      &platform_, &crypto_,
      AsyncInitPtr<BiometricsAuthBlockService>(bio_service_.get()),
      &mock_user_metadata_reader_);
  AuthFactorDriver& driver = fp_driver;

  EXPECT_CALL(platform_, FileExists(base::FilePath(
                             "/var/lib/cryptohome/fingerprint_decrypt_enable")))
      .WillOnce(Return(false));
  EXPECT_THAT(driver.IsFullAuthAllowed(AuthIntent::kDecrypt), IsFalse());
  EXPECT_THAT(driver.IsFullAuthAllowed(AuthIntent::kVerifyOnly), IsTrue());

  EXPECT_CALL(platform_, FileExists(base::FilePath(
                             "/var/lib/cryptohome/fingerprint_decrypt_enable")))
      .WillOnce(Return(true));
  EXPECT_THAT(driver.IsFullAuthAllowed(AuthIntent::kDecrypt), IsTrue());
  EXPECT_THAT(driver.IsFullAuthAllowed(AuthIntent::kVerifyOnly), IsTrue());
}

}  // namespace
}  // namespace cryptohome
