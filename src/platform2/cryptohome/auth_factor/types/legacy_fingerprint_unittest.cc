// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/legacy_fingerprint.h"

#include <utility>
#include <variant>
#include <vector>

#include <base/functional/callback.h>
#include <base/test/test_future.h>
#include <brillo/cryptohome.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_factor/types/test_utils.h"
#include "cryptohome/mock_fingerprint_manager.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::Optional;

class LegacyFingerprintDriverTest : public AuthFactorDriverGenericTest {
 protected:
  MockFingerprintManager fp_manager_;
  FingerprintAuthBlockService fp_service_{
      AsyncInitPtr<FingerprintManager>(&fp_manager_),
      base::BindRepeating(&LegacyFingerprintDriverTest::HandleSignal,
                          base::Unretained(this))};

  // Handle the signals sent by the auth block service, by capturing the result.
  std::vector<user_data_auth::FingerprintScanResult> signal_results_;
  void HandleSignal(user_data_auth::FingerprintScanResult result) {
    signal_results_.push_back(std::move(result));
  }
};

TEST_F(LegacyFingerprintDriverTest, ConvertToProto) {
  // Setup
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;
  AuthFactorMetadata metadata = CreateMetadataWithType<std::monostate>();

  // Test
  std::optional<user_data_auth::AuthFactor> proto =
      driver.ConvertToProto(kLabel, metadata);

  // Verify
  ASSERT_THAT(proto, Optional(_));
  EXPECT_THAT(proto.value().type(),
              Eq(user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT));
  EXPECT_THAT(proto.value().label(), Eq(kLabel));
  EXPECT_THAT(proto->common_metadata().chromeos_version_last_updated(),
              Eq(kChromeosVersion));
  EXPECT_THAT(proto->common_metadata().chrome_version_last_updated(),
              Eq(kChromeVersion));
  EXPECT_THAT(proto->common_metadata().lockout_policy(),
              Eq(user_data_auth::LOCKOUT_POLICY_NONE));
}

TEST_F(LegacyFingerprintDriverTest, UnsupportedWithVk) {
  // Setup
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  // Test, Verify.
  EXPECT_THAT(
      driver.IsSupportedByStorage({AuthFactorStorageType::kVaultKeyset}, {}),
      IsFalse());
}

TEST_F(LegacyFingerprintDriverTest, UnsupportedWithUss) {
  // Setup
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  // Test, Verify.
  EXPECT_THAT(driver.IsSupportedByStorage(
                  {AuthFactorStorageType::kUserSecretStash}, {}),
              IsFalse());
}

TEST_F(LegacyFingerprintDriverTest, UnsupportedByHardware) {
  // Setup
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  // Test, Verify.
  EXPECT_THAT(driver.IsSupportedByHardware(), IsFalse());
}

TEST_F(LegacyFingerprintDriverTest, PrepareForAddFails) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAdd(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(LegacyFingerprintDriverTest, PrepareForAuthCannotStart) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  EXPECT_CALL(fp_manager_, StartAuthSessionAsyncForUser(kObfuscatedUser, _))
      .WillOnce([](ObfuscatedUsername username,
                   FingerprintManager::StartSessionCallback callback) {
        std::move(callback).Run(false);
      });

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get(), NotOk());
  EXPECT_THAT(prepare_result.Get().status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
}

TEST_F(LegacyFingerprintDriverTest, PrepareForAuthFailure) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  EXPECT_CALL(fp_manager_, StartAuthSessionAsyncForUser(kObfuscatedUser, _))
      .WillOnce([](ObfuscatedUsername username,
                   FingerprintManager::StartSessionCallback callback) {
        std::move(callback).Run(true);
      });
  EXPECT_CALL(fp_manager_, SetSignalCallback(_))
      .WillOnce([](FingerprintManager::SignalCallback callback) {
        std::move(callback).Run(
            FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
      });

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get(), IsOk());
  EXPECT_THAT(signal_results_,
              ElementsAre(user_data_auth::FINGERPRINT_SCAN_RESULT_LOCKOUT));
}

TEST_F(LegacyFingerprintDriverTest, PrepareForAuthSuccess) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  EXPECT_CALL(fp_manager_, StartAuthSessionAsyncForUser(kObfuscatedUser, _))
      .WillOnce([](ObfuscatedUsername username,
                   FingerprintManager::StartSessionCallback callback) {
        std::move(callback).Run(true);
      });
  EXPECT_CALL(fp_manager_, SetSignalCallback(_))
      .WillOnce([](FingerprintManager::SignalCallback callback) {
        std::move(callback).Run(FingerprintScanStatus::SUCCESS);
      });

  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  driver.PrepareForAuthenticate(kObfuscatedUser, prepare_result.GetCallback());
  EXPECT_THAT(prepare_result.Get(), IsOk());
  EXPECT_THAT(signal_results_,
              ElementsAre(user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS));
}

TEST_F(LegacyFingerprintDriverTest, GetDelayFails) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  AuthFactor factor(AuthFactorType::kLegacyFingerprint, "",
                    CreateMetadataWithType<std::monostate>(),
                    {.state = std::monostate()});

  auto delay_in_ms = driver.GetFactorDelay(kObfuscatedUser, factor);
  ASSERT_THAT(delay_in_ms, NotOk());
  EXPECT_THAT(delay_in_ms.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

TEST_F(LegacyFingerprintDriverTest, GetExpirationFails) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  AuthFactor factor(AuthFactorType::kLegacyFingerprint, "",
                    CreateMetadataWithType<std::monostate>(),
                    {.state = std::monostate()});

  auto expired = driver.IsExpired(kObfuscatedUser, factor);
  ASSERT_THAT(expired, NotOk());
  EXPECT_THAT(expired.status()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

// Verify that the legacy fingerprint verifier cannot be created with a label.
TEST_F(LegacyFingerprintDriverTest, CreateCredentialVerifierFailsWithLabel) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  auto verifier = driver.CreateCredentialVerifier("not-blank", {});
  EXPECT_THAT(verifier, IsNull());
}

TEST_F(LegacyFingerprintDriverTest, CreateCredentialVerifier) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  auto verifier = driver.CreateCredentialVerifier("", {});
  ASSERT_THAT(verifier, NotNull());
  EXPECT_THAT(verifier->auth_factor_type(),
              Eq(AuthFactorType::kLegacyFingerprint));
  EXPECT_THAT(verifier->auth_factor_label(), Eq(""));

  EXPECT_CALL(fp_manager_, StartAuthSessionAsyncForUser(kObfuscatedUser, _))
      .WillOnce([](ObfuscatedUsername username,
                   FingerprintManager::StartSessionCallback callback) {
        std::move(callback).Run(true);
      });
  EXPECT_CALL(fp_manager_, SetSignalCallback(_))
      .WillOnce([](FingerprintManager::SignalCallback callback) {
        std::move(callback).Run(FingerprintScanStatus::SUCCESS);
      });
  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  fp_service_.Start(kObfuscatedUser, prepare_result.GetCallback());
  ASSERT_THAT(prepare_result.Get(), IsOk());
  auto token = std::move(*prepare_result.Take());
  TestFuture<CryptohomeStatus> good_result;
  verifier->Verify({}, good_result.GetCallback());
  EXPECT_THAT(good_result.Get(), IsOk());
  EXPECT_CALL(fp_manager_, EndAuthSession());
  CryptohomeStatus status = token->Terminate();
  EXPECT_THAT(status, IsOk());
}

TEST_F(LegacyFingerprintDriverTest, CreateCredentialVerifierWithBadAuth) {
  LegacyFingerprintAuthFactorDriver legacy_fp_driver(&fp_service_);
  AuthFactorDriver& driver = legacy_fp_driver;

  auto verifier = driver.CreateCredentialVerifier("", {});
  ASSERT_THAT(verifier, NotNull());
  EXPECT_THAT(verifier->auth_factor_type(),
              Eq(AuthFactorType::kLegacyFingerprint));
  EXPECT_THAT(verifier->auth_factor_label(), Eq(""));

  EXPECT_CALL(fp_manager_, StartAuthSessionAsyncForUser(kObfuscatedUser, _))
      .WillOnce([](ObfuscatedUsername username,
                   FingerprintManager::StartSessionCallback callback) {
        std::move(callback).Run(true);
      });
  EXPECT_CALL(fp_manager_, SetSignalCallback(_))
      .WillOnce([](FingerprintManager::SignalCallback callback) {
        std::move(callback).Run(
            FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
      });
  TestFuture<CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>>
      prepare_result;
  fp_service_.Start(kObfuscatedUser, prepare_result.GetCallback());
  ASSERT_THAT(prepare_result.Get(), IsOk());
  auto token = std::move(*prepare_result.Take());
  TestFuture<CryptohomeStatus> bad_result;
  verifier->Verify({}, bad_result.GetCallback());
  EXPECT_THAT(bad_result.Get(), NotOk());
  EXPECT_THAT(bad_result.Get()->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_DENIED));
  EXPECT_CALL(fp_manager_, EndAuthSession());
  CryptohomeStatus status = token->Terminate();
  EXPECT_THAT(status, IsOk());
}

}  // namespace
}  // namespace cryptohome
