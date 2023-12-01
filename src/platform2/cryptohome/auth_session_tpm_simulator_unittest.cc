// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for `AuthSession`. Unlike auth_session_unittest.cc, uses TPM
// simulator and minimal mocking in order to be able to verify inter-class
// interactions.

#include <memory>
#include <string>
#include <tuple>

#include <base/files/scoped_temp_dir.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_piece.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/secure_blob.h>
#include <cryptohome/cryptorecovery/cryptorecovery.pb.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/backend/mock_backend.h>
#include <libhwsec/factory/tpm2_simulator_factory_for_test.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/frontend/pinweaver/frontend.h>
#include <libhwsec/frontend/recovery_crypto/frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/auth_block_utility_impl.h"
#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/types/manager.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/auth_session.h"
#include "cryptohome/crypto.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/cryptorecovery/fake_recovery_mediator_crypto.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/fake_platform.h"
#include "cryptohome/features.h"
#include "cryptohome/le_credential_manager_impl.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/user_session/user_session_map.h"
#include "cryptohome/vault_keyset_factory.h"

namespace cryptohome {
namespace {

using ::base::test::TestFuture;
using ::cryptohome::cryptorecovery::FakeRecoveryMediatorCrypto;
using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::hwsec_foundation::status::MakeStatus;
using ::testing::Combine;
using ::testing::NiceMock;
using ::testing::ValuesIn;

constexpr int kPinResetCounter = 6;

constexpr AuthFactorStorageType kAllAuthFactorStorageFromTypes[] = {
    AuthFactorStorageType::kVaultKeyset,
    AuthFactorStorageType::kUserSecretStash,
};

constexpr AuthFactorStorageType kAllAuthFactorStorageToTypes[] = {
    AuthFactorStorageType::kUserSecretStash,
};

constexpr char kPasswordLabel[] = "fake-password-label";
constexpr char kPassword[] = "fake-password";
constexpr char kNewPassword[] = "fake-new-password";

constexpr char kPinLabel[] = "fake-pin-label";
constexpr char kPin[] = "1234";
constexpr char kNewPin[] = "1111";

constexpr char kRecoveryLabel[] = "fake-recovery-label";
constexpr char kUserGaiaId[] = "fake-gaia-id";
constexpr char kDeviceUserId[] = "fake-device-user-id";

CryptohomeStatus MakeFakeCryptohomeError() {
  CryptohomeError::ErrorLocationPair fake_error_location(
      static_cast<CryptohomeError::ErrorLocation>(1), "FakeErrorLocation");
  return MakeStatus<CryptohomeError>(fake_error_location, ErrorActionSet());
}

CryptohomeStatus RunAddAuthFactor(
    const user_data_auth::AddAuthFactorRequest& request,
    AuthSession& auth_session) {
  TestFuture<CryptohomeStatus> future;
  auth_session.AddAuthFactor(request, future.GetCallback());
  return future.Take();
}

CryptohomeStatus RunAuthenticateAuthFactor(
    const user_data_auth::AuthenticateAuthFactorRequest& request,
    AuthSession& auth_session) {
  // Convert |auth_factor_label| or |auth_factor_labels| into an array.
  std::vector<std::string> auth_factor_labels;
  if (!request.auth_factor_label().empty()) {
    auth_factor_labels.push_back(request.auth_factor_label());
  } else {
    for (auto label : request.auth_factor_labels()) {
      auth_factor_labels.push_back(label);
    }
  }
  TestFuture<CryptohomeStatus> future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, request.auth_input(),
                                      future.GetCallback());
  return future.Take();
}

CryptohomeStatus RunUpdateAuthFactor(
    const user_data_auth::UpdateAuthFactorRequest& request,
    AuthSession& auth_session) {
  TestFuture<CryptohomeStatus> future;
  auth_session.UpdateAuthFactor(request, future.GetCallback());
  return future.Take();
}

CryptohomeStatus AddPasswordFactor(const std::string& label,
                                   const std::string& password,
                                   AuthSession& auth_session) {
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  user_data_auth::AuthFactor& factor = *request.mutable_auth_factor();
  factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  factor.set_label(label);
  factor.mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(password);
  return RunAddAuthFactor(request, auth_session);
}

CryptohomeStatus AuthenticatePasswordFactor(const std::string& label,
                                            const std::string& password,
                                            AuthSession& auth_session) {
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(label);
  request.mutable_auth_input()->mutable_password_input()->set_secret(password);
  return RunAuthenticateAuthFactor(request, auth_session);
}

CryptohomeStatus UpdatePasswordFactor(const std::string& label,
                                      const std::string& new_password,
                                      AuthSession& auth_session) {
  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(label);
  user_data_auth::AuthFactor& factor = *request.mutable_auth_factor();
  factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  factor.set_label(label);
  factor.mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(
      new_password);
  return RunUpdateAuthFactor(request, auth_session);
}

CryptohomeStatus UpdatePinFactor(const std::string& label,
                                 const std::string& new_pin,
                                 AuthSession& auth_session) {
  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(label);
  user_data_auth::AuthFactor& factor = *request.mutable_auth_factor();
  factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  factor.set_label(label);
  factor.mutable_pin_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(new_pin);
  return RunUpdateAuthFactor(request, auth_session);
}

CryptohomeStatus AddPinFactor(const std::string& label,
                              const std::string& pin,
                              AuthSession& auth_session) {
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  user_data_auth::AuthFactor& factor = *request.mutable_auth_factor();
  factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  factor.set_label(label);
  factor.mutable_pin_metadata();
  request.mutable_auth_input()->mutable_pin_input()->set_secret(pin);
  return RunAddAuthFactor(request, auth_session);
}

CryptohomeStatus AuthenticatePinFactor(const std::string& label,
                                       const std::string& pin,
                                       AuthSession& auth_session) {
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(label);
  request.mutable_auth_input()->mutable_pin_input()->set_secret(pin);
  return RunAuthenticateAuthFactor(request, auth_session);
}

CryptohomeStatus AddRecoveryFactor(AuthSession& auth_session) {
  brillo::SecureBlob mediator_pub_key;
  EXPECT_TRUE(
      FakeRecoveryMediatorCrypto::GetFakeMediatorPublicKey(&mediator_pub_key));

  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  user_data_auth::AuthFactor& factor = *request.mutable_auth_factor();
  factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY);
  factor.set_label(kRecoveryLabel);
  factor.mutable_cryptohome_recovery_metadata();
  user_data_auth::CryptohomeRecoveryAuthInput& input =
      *request.mutable_auth_input()->mutable_cryptohome_recovery_input();
  input.set_mediator_pub_key(mediator_pub_key.to_string());
  input.set_user_gaia_id(kUserGaiaId);
  input.set_device_user_id(kDeviceUserId);
  return RunAddAuthFactor(request, auth_session);
}

CryptohomeStatus AuthenticateRecoveryFactor(AuthSession& auth_session) {
  // Retrieve fake server parameters.
  brillo::SecureBlob epoch_pub_key;
  EXPECT_TRUE(
      FakeRecoveryMediatorCrypto::GetFakeEpochPublicKey(&epoch_pub_key));
  brillo::SecureBlob epoch_priv_key;
  EXPECT_TRUE(
      FakeRecoveryMediatorCrypto::GetFakeEpochPrivateKey(&epoch_priv_key));
  brillo::SecureBlob mediator_priv_key;
  EXPECT_TRUE(FakeRecoveryMediatorCrypto::GetFakeMediatorPrivateKey(
      &mediator_priv_key));
  cryptorecovery::CryptoRecoveryEpochResponse epoch_response;
  EXPECT_TRUE(
      FakeRecoveryMediatorCrypto::GetFakeEpochResponse(&epoch_response));

  // Obtain request for the server.
  user_data_auth::GetRecoveryRequestRequest get_recovery_request;
  get_recovery_request.set_auth_session_id(auth_session.serialized_token());
  get_recovery_request.set_auth_factor_label(kRecoveryLabel);
  get_recovery_request.set_epoch_response(epoch_response.SerializeAsString());
  TestFuture<user_data_auth::GetRecoveryRequestReply> recovery_request_future;
  auth_session.GetRecoveryRequest(
      get_recovery_request,
      recovery_request_future
          .GetCallback<const user_data_auth::GetRecoveryRequestReply&>());
  EXPECT_FALSE(recovery_request_future.Get().has_error_info());
  cryptorecovery::CryptoRecoveryRpcRequest recovery_request;
  EXPECT_TRUE(recovery_request.ParseFromString(
      recovery_request_future.Get().recovery_request()));

  // Create fake server.
  std::unique_ptr<FakeRecoveryMediatorCrypto> recovery_crypto =
      FakeRecoveryMediatorCrypto::Create();
  if (!recovery_crypto) {
    ADD_FAILURE() << "FakeRecoveryMediatorCrypto::Create failed";
    return MakeFakeCryptohomeError();
  }

  // Generate fake server reply.
  cryptorecovery::CryptoRecoveryRpcResponse recovery_response;
  EXPECT_TRUE(recovery_crypto->MediateRequestPayload(
      epoch_pub_key, epoch_priv_key, mediator_priv_key, recovery_request,
      &recovery_response));

  // Authenticate auth factor.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kRecoveryLabel);
  user_data_auth::CryptohomeRecoveryAuthInput& input =
      *request.mutable_auth_input()->mutable_cryptohome_recovery_input();
  input.set_epoch_response(epoch_response.SerializeAsString());
  input.set_recovery_response(recovery_response.SerializeAsString());
  auto ledger_info = FakeRecoveryMediatorCrypto::GetLedgerInfo();
  input.mutable_ledger_info()->set_name(ledger_info.name);
  input.mutable_ledger_info()->set_key_hash(ledger_info.key_hash.value());
  input.mutable_ledger_info()->set_public_key(
      ledger_info.public_key.value().to_string());
  return RunAuthenticateAuthFactor(request, auth_session);
}

// Fixture for testing `AuthSession` against TPM simulator and real
// implementations of auth blocks, UserSecretStash and VaultKeysets.
//
// This integration-like test is more expensive, but allows to check the code
// passes data and uses other class APIs correctly.
class AuthSessionWithTpmSimulatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // TODO(b/254864841): Remove this after le_credential code is migrated to
    // use `Platform` instead of direct file operations in system-global paths.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    crypto_.set_le_manager_for_testing(
        std::make_unique<LECredentialManagerImpl>(
            hwsec_pinweaver_frontend_.get(),
            temp_dir_.GetPath().AppendASCII("low_entropy_creds")));

    // TODO(b/266217791): The simulator factory should instead do it itself.
    ON_CALL(hwsec_simulator_factory_.GetMockBackend().GetMock().vendor,
            GetManufacturer)
        .WillByDefault(ReturnValue(0x43524F53));

    crypto_.Init();
  }

  const Username kUsername{"foo@example.com"};

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  // TPM simulator objects.
  hwsec::Tpm2SimulatorFactoryForTest hwsec_simulator_factory_;
  std::unique_ptr<const hwsec::CryptohomeFrontend> hwsec_cryptohome_frontend_ =
      hwsec_simulator_factory_.GetCryptohomeFrontend();
  std::unique_ptr<const hwsec::PinWeaverFrontend> hwsec_pinweaver_frontend_ =
      hwsec_simulator_factory_.GetPinWeaverFrontend();
  std::unique_ptr<const hwsec::RecoveryCryptoFrontend>
      hwsec_recovery_crypto_frontend_ =
          hwsec_simulator_factory_.GetRecoveryCryptoFrontend();

  // TODO(b/254864841): Remove this after le_credential code is migrated to use
  // `Platform` instead of direct file operations.
  base::ScopedTempDir temp_dir_;

  // AuthSession dependencies.
  FakePlatform platform_;
  CryptohomeKeysManager cryptohome_keys_manager_{
      hwsec_cryptohome_frontend_.get(), &platform_};
  Crypto crypto_{hwsec_cryptohome_frontend_.get(),
                 hwsec_pinweaver_frontend_.get(), &cryptohome_keys_manager_,
                 hwsec_recovery_crypto_frontend_.get()};
  UserSessionMap user_session_map_;
  KeysetManagement keyset_management_{&platform_, &crypto_,
                                      std::make_unique<VaultKeysetFactory>()};
  FakeFeaturesForTesting features_;
  std::unique_ptr<FingerprintAuthBlockService> fp_service_{
      FingerprintAuthBlockService::MakeNullService()};
  AuthBlockUtilityImpl auth_block_utility_{
      &keyset_management_,
      &crypto_,
      &platform_,
      &features_.async,
      AsyncInitPtr<ChallengeCredentialsHelper>(nullptr),
      nullptr,
      AsyncInitPtr<BiometricsAuthBlockService>(nullptr)};
  AuthFactorDriverManager auth_factor_driver_manager_{
      &platform_,
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(nullptr),
      nullptr,
      fp_service_.get(),
      AsyncInitPtr<BiometricsAuthBlockService>(nullptr),
      nullptr};
  AuthFactorManager auth_factor_manager_{&platform_};
  UserSecretStashStorage user_secret_stash_storage_{&platform_};
  UserMetadataReader user_metadata_reader_{&user_secret_stash_storage_};

  AuthSession::BackingApis backing_apis_{&crypto_,
                                         &platform_,
                                         &user_session_map_,
                                         &keyset_management_,
                                         &auth_block_utility_,
                                         &auth_factor_driver_manager_,
                                         &auth_factor_manager_,
                                         &user_secret_stash_storage_,
                                         &user_metadata_reader_,
                                         &features_.async};
};

class AuthSessionWithTpmSimulatorUssMigrationTest
    : public AuthSessionWithTpmSimulatorTest {
 protected:
  // Configures the experiment states to the desired storage type.
  void SetStorageType(AuthFactorStorageType storage_type) {
    // Decide whether to enable both of USS experiments (for new users and for
    // existing ones). The test doesn't support switching them in isolation.
    bool enable_uss = storage_type == AuthFactorStorageType::kUserSecretStash;

    // First destroy the old override, if present, as having two overrides with
    // non-nested lifetimes isn't supported.
    uss_experiment_override_.reset();
    uss_experiment_override_ =
        std::make_unique<SetUssExperimentOverride>(enable_uss);

    features_.SetDefaultForFeature(Features::kUSSMigration,
                                   /*enabled=*/true);
  }

 private:
  std::unique_ptr<SetUssExperimentOverride> uss_experiment_override_;
};

// Parameterized fixture for tests that should work regardless of the
// UserSecretStash migration state, i.e. for all 4 combinations (VK/USS used
// initially/finally).
//
// Note that this kind of test skips this combination: USS is enabled for new
// users but the USS migration of the existing users is disabled.
class AuthSessionWithTpmSimulatorUssMigrationAgnosticTest
    : public AuthSessionWithTpmSimulatorUssMigrationTest,
      public ::testing::WithParamInterface<
          std::tuple<AuthFactorStorageType, AuthFactorStorageType>> {
 protected:
  static AuthFactorStorageType storage_type_initially() {
    return std::get<0>(GetParam());
  }
  static AuthFactorStorageType storage_type_finally() {
    return std::get<1>(GetParam());
  }

  // Aliases to `SetStorageType()` that call it with the corresponding test
  // parameter.
  void SetToInitialStorageType() { SetStorageType(storage_type_initially()); }
  void SetToFinalStorageType() { SetStorageType(storage_type_finally()); }

 private:
  std::unique_ptr<SetUssExperimentOverride> uss_experiment_override_;
};

// Test that it's possible to migrate PIN from VaultKeyset to UserSecretStash
// even after the password was already migrated and recovery (a USS-only factor)
// was added and used as well.
TEST_F(AuthSessionWithTpmSimulatorUssMigrationTest,
       CompleteUssMigrationAfterRecoveryMidWay) {
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  //  Assert. Create a user with password and PIN VKs.
  SetStorageType(AuthFactorStorageType::kVaultKeyset);
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
    EXPECT_THAT(AddPinFactor(kPinLabel, kPin, *auth_session), IsOk());
  }

  // Act. Enable USS experiment, add recovery (after using the password and
  // hence migrating it to USS), and use recovery to update the password.
  SetStorageType(AuthFactorStorageType::kUserSecretStash);
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    EXPECT_THAT(AddRecoveryFactor(*auth_session), IsOk());
  }
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(AuthenticateRecoveryFactor(*auth_session), IsOk());
    EXPECT_THAT(
        UpdatePasswordFactor(kPasswordLabel, kNewPassword, *auth_session),
        IsOk());
  }

  // Assert. Both password (already migrated to USS) and PIN (not migrated yet)
  // still work.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kNewPassword, *auth_session),
        IsOk());
  }
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kPin, *auth_session), IsOk());
  }
}

// Test that it's possible to migrate a locked-out PIN from VaultKeyset to
// UserSecretStash even after the password was already migrated and recovery (a
// USS-only factor) was added and used as well.
TEST_F(AuthSessionWithTpmSimulatorUssMigrationTest,
       CompleteLockedPinUssMigrationAfterRecoveryMidWay) {
  constexpr char kWrongPin[] = "0000";
  static_assert(base::StringPiece(kWrongPin) != base::StringPiece(kPin),
                "Bad kWrongPin");
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  // Arrange. Create a user with password and PIN VKs.
  SetStorageType(AuthFactorStorageType::kVaultKeyset);
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
    EXPECT_THAT(AddPinFactor(kPinLabel, kPin, *auth_session), IsOk());
  }

  // Act. Enable USS experiment, add recovery (after using the password and
  // hence migrating it to USS).
  SetStorageType(AuthFactorStorageType::kUserSecretStash);
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    EXPECT_THAT(AddRecoveryFactor(*auth_session), IsOk());
  }
  // Lock out the PIN factor.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    for (int i = 0; i < kPinResetCounter; ++i) {
      EXPECT_THAT(AuthenticatePinFactor(kPinLabel, "0", *auth_session),
                  NotOk());
    }
    EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kPin, *auth_session), NotOk());
  }
  // Authenticate via password.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
  }

  // Assert. The PIN (not migrated yet) still works.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kPin, *auth_session), IsOk());
  }
}

INSTANTIATE_TEST_SUITE_P(
    All,
    AuthSessionWithTpmSimulatorUssMigrationAgnosticTest,
    Combine(ValuesIn(kAllAuthFactorStorageFromTypes),
            ValuesIn(kAllAuthFactorStorageToTypes)),
    [](auto info) {
      // Return human-readable parameterized test name. Use caps in order to
      // clearly separate lowercase words visually.
      return base::StringPrintf(
          "%sTHEN%s",
          AuthFactorStorageTypeToDebugString(std::get<0>(info.param)),
          AuthFactorStorageTypeToDebugString(std::get<1>(info.param)));
    });

// Test that authentication via a previously added password works.
TEST_P(AuthSessionWithTpmSimulatorUssMigrationAgnosticTest,
       AuthenticateViaPassword) {
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  // Arrange.
  // Configure the creation via USS or VK, depending on the first test
  // parameter.
  SetToInitialStorageType();
  {
    // Create a user with a password factor.
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
  }
  // Configure whether authenticating via USS is allowed, or VK should be used
  // (regardless of whether it's backup or not).
  SetToFinalStorageType();
  // Create a new AuthSession for authentication.
  std::unique_ptr<AuthSession> auth_session = create_auth_session();
  ASSERT_TRUE(auth_session);

  // Act.
  CryptohomeStatus auth_status =
      AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session);

  // Assert.
  EXPECT_THAT(auth_status, IsOk());
}

// Test that updating via a previously added password works correctly: you can
// authenticate via the new password but not via the old one.
TEST_P(AuthSessionWithTpmSimulatorUssMigrationAgnosticTest, UpdatePassword) {
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  // Arrange.
  // Configure the creation via USS or VK, depending on the first test
  // parameter.
  SetToInitialStorageType();
  {
    // Create a user with a password factor.
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
  }
  // Switch to the new backend (USS or VK) depending on the second test
  // parameter).
  SetToFinalStorageType();

  // Act.
  // Update the password factor after authenticating via the old password.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    EXPECT_THAT(
        UpdatePasswordFactor(kPasswordLabel, kNewPassword, *auth_session),
        IsOk());
  }

  // Assert.
  auto try_authenticate = [&](const std::string& password) {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    if (!auth_session) {
      ADD_FAILURE() << "Failed to create AuthSession";
      return MakeFakeCryptohomeError();
    }
    return AuthenticatePasswordFactor(kPasswordLabel, password, *auth_session);
  };
  // Check the old password isn't accepted, but the new one is.
  EXPECT_THAT(try_authenticate(kPassword), NotOk());
  EXPECT_THAT(try_authenticate(kNewPassword), IsOk());
  // Check the same holds after switching back to the initial storage type.
  SetToInitialStorageType();
  EXPECT_THAT(try_authenticate(kPassword), NotOk());
}

// Test a password factor can be successfully updated after authenticating via a
// recovery factor.
TEST_P(AuthSessionWithTpmSimulatorUssMigrationAgnosticTest,
       UpdatePasswordAfterRecoveryAuth) {
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  // Arrange.
  // Create a user with a password factor. Configure the creation via USS or VK,
  // depending on the first test parameter.
  SetToInitialStorageType();
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
  }
  // Add a recovery factor after authenticating via the password. Do this with
  // the USS usage configured, since recovery isn't supported on VKs.
  SetStorageType(AuthFactorStorageType::kUserSecretStash);
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    EXPECT_THAT(AddRecoveryFactor(*auth_session), IsOk());
    // Adding recovery factor removes the backup keyset.
    EXPECT_EQ(nullptr,
              keyset_management_.GetVaultKeyset(
                  auth_session->obfuscated_username(), kPasswordLabel));
  }

  // Test.
  // Update password after authenticating via recovery.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(AuthenticateRecoveryFactor(*auth_session), IsOk());
    EXPECT_THAT(
        UpdatePasswordFactor(kPasswordLabel, kNewPassword, *auth_session),
        IsOk());
  }

  // Verify.
  // Check the old password isn't accepted, meanwhile the new one does.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        NotOk());
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kNewPassword, *auth_session),
        IsOk());
  }
  // Check the old password isn't accepted even after switching back to the
  // original storage type. Note that we don't check the new password since, due
  // to implementation limitation, this is not guaranteed to work in the
  // rollback scenario with USS-only factors (see b/262632342).
  SetToInitialStorageType();
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        NotOk());
  }
}

// Test that updating via a previously added password works correctly: you can
// authenticate via the new password but not via the old one. All this while Pin
// is not migrated.
TEST_P(AuthSessionWithTpmSimulatorUssMigrationAgnosticTest,
       UpdatePasswordPartialMigration) {
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  // Arrange.
  // Configure the creation via USS or VK, depending on the first test
  // parameter.
  SetToInitialStorageType();
  {
    // Create a user with a password factor.
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
    EXPECT_THAT(AddPinFactor(kPinLabel, kPin, *auth_session), IsOk());
  }
  // Switch to the new backend (USS or VK) depending on the second test
  // parameter).
  SetToFinalStorageType();

  // Act.
  // Update the password factor after authenticating via the old password.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    EXPECT_THAT(
        UpdatePasswordFactor(kPasswordLabel, kNewPassword, *auth_session),
        IsOk());
  }

  // Assert.
  auto try_authenticate = [&](const std::string& password) {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    if (!auth_session) {
      ADD_FAILURE() << "Failed to create AuthSession";
      return MakeFakeCryptohomeError();
    }
    return AuthenticatePasswordFactor(kPasswordLabel, password, *auth_session);
  };
  // Check the old password isn't accepted, but the new one is.
  EXPECT_THAT(try_authenticate(kPassword), NotOk());
  EXPECT_THAT(try_authenticate(kNewPassword), IsOk());

  // Expect Pin can be authenticated still.
  std::unique_ptr<AuthSession> auth_session = create_auth_session();
  ASSERT_TRUE(auth_session);
  EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kPin, *auth_session), IsOk());
}

// Test that updating via a previously added PIN works correctly: you can
// authenticate via the new PIN but not via the old one. Update migrates the
// PIN.
TEST_P(AuthSessionWithTpmSimulatorUssMigrationAgnosticTest,
       UpdatePinPartialMigration) {
  auto create_auth_session = [this]() {
    return AuthSession::Create(kUsername,
                               user_data_auth::AUTH_SESSION_FLAGS_NONE,
                               AuthIntent::kDecrypt, backing_apis_);
  };

  // Arrange.
  // Configure the creation via USS or VK, depending on the first test
  // parameter.
  SetToInitialStorageType();
  {
    // Create a user with a password and PIN factor.
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_THAT(AddPasswordFactor(kPasswordLabel, kPassword, *auth_session),
                IsOk());
    EXPECT_THAT(AddPinFactor(kPinLabel, kPin, *auth_session), IsOk());
  }
  // Switch to the new backend (USS or VK) depending on the second test
  // parameter).
  SetToFinalStorageType();

  // Act.
  // Update the PIN factor after authenticating via the password.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    EXPECT_THAT(UpdatePinFactor(kPinLabel, kNewPin, *auth_session), IsOk());
  }

  // Assert.
  auto try_authenticate = [&](const std::string& pin) {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    if (!auth_session) {
      ADD_FAILURE() << "Failed to create AuthSession";
      return MakeFakeCryptohomeError();
    }
    return AuthenticatePinFactor(kPinLabel, pin, *auth_session);
  };
  // Check the old PIN isn't accepted, but the new one is.
  EXPECT_THAT(try_authenticate(kPin), NotOk());
  EXPECT_THAT(try_authenticate(kNewPin), IsOk());

  // Lockout PIN by attempting authenticate with wrong PINs.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    for (int i = 0; i < kPinResetCounter; i++) {
      EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kPin, *auth_session),
                  NotOk());
    }
    EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kNewPin, *auth_session),
                NotOk());
  }

  // Test that password resets the counter.
  {
    std::unique_ptr<AuthSession> auth_session = create_auth_session();
    ASSERT_TRUE(auth_session);
    EXPECT_THAT(
        AuthenticatePasswordFactor(kPasswordLabel, kPassword, *auth_session),
        IsOk());
    // Verify that authenticate with correct PIN succeed after the counter is
    // reset.
    EXPECT_THAT(AuthenticatePinFactor(kPinLabel, kNewPin, *auth_session),
                IsOk());
  }
}

}  // namespace
}  // namespace cryptohome
