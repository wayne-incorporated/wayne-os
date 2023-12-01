// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/manager.h"
#include "cryptohome/userdataauth.h"

#include <memory>
#include <utility>

#include <base/containers/span.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/bind.h>
#include <base/test/mock_callback.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gmock/gmock-matchers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/auth_block_utility_impl.h"
#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_blocks/mock_auth_block_utility.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/auth_session.h"
#include "cryptohome/auth_session_manager.h"
#include "cryptohome/cleanup/mock_user_oldest_activity_timestamp_manager.h"
#include "cryptohome/crypto.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/features.h"
#include "cryptohome/mock_credential_verifier.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_install_attributes.h"
#include "cryptohome/mock_keyset_management.h"
#include "cryptohome/mock_le_credential_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/pkcs11/mock_pkcs11_token_factory.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/mock_homedirs.h"
#include "cryptohome/storage/mock_mount.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/user_session/mock_user_session.h"
#include "cryptohome/user_session/mock_user_session_factory.h"
#include "cryptohome/user_session/real_user_session.h"
#include "cryptohome/user_session/user_session_map.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {

using ::testing::_;
using ::testing::An;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::UnorderedElementsAre;

using base::test::TaskEnvironment;
using base::test::TestFuture;
using brillo::cryptohome::home::SanitizeUserName;
using error::CryptohomeCryptoError;
using error::CryptohomeError;
using error::CryptohomeMountError;
using hwsec::TPMError;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;
using hwsec_foundation::error::testing::ReturnValue;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using user_data_auth::AUTH_INTENT_DECRYPT;
using user_data_auth::AUTH_INTENT_VERIFY_ONLY;
using user_data_auth::AUTH_INTENT_WEBAUTHN;
using user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_EPHEMERAL_USER;

namespace {

using AuthenticateAuthFactorCallback = base::OnceCallback<void(
    const user_data_auth::AuthenticateAuthFactorReply&)>;
using AddAuthFactorCallback =
    base::OnceCallback<void(const user_data_auth::AddAuthFactorReply&)>;

constexpr char kPassword[] = "password";
constexpr char kPassword2[] = "password2";
constexpr char kPassword3[] = "password3";
constexpr char kPasswordLabel[] = "fake-password-label";
// 300 seconds should be left right as we authenticate.
constexpr int time_left_after_authenticate = 300;
constexpr char kPasswordLabel2[] = "fake-password-label2";

SerializedVaultKeyset CreateFakePasswordVk(const std::string& label) {
  SerializedVaultKeyset serialized_vk;
  serialized_vk.set_flags(SerializedVaultKeyset::TPM_WRAPPED |
                          SerializedVaultKeyset::SCRYPT_DERIVED |
                          SerializedVaultKeyset::PCR_BOUND |
                          SerializedVaultKeyset::ECC);
  serialized_vk.set_password_rounds(1);
  serialized_vk.set_tpm_key("tpm-key");
  serialized_vk.set_extended_tpm_key("tpm-extended-key");
  serialized_vk.set_vkk_iv("iv");
  serialized_vk.set_wrapped_reset_seed("wrapped-reset-seed");
  serialized_vk.mutable_key_data()->set_type(KeyData::KEY_TYPE_PASSWORD);
  serialized_vk.mutable_key_data()->set_label(label);
  return serialized_vk;
}

void MockVKToAuthFactorMapLoading(
    const ObfuscatedUsername& obfuscated_username,
    const std::vector<SerializedVaultKeyset>& serialized_vks,
    MockKeysetManagement& keyset_management) {
  std::vector<int> key_indices;
  for (size_t index = 0; index < serialized_vks.size(); ++index) {
    key_indices.push_back(index);
  }
  EXPECT_CALL(keyset_management, GetVaultKeysets(obfuscated_username, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(key_indices), Return(true)));

  for (size_t index = 0; index < serialized_vks.size(); ++index) {
    const auto& serialized_vk = serialized_vks[index];
    EXPECT_CALL(keyset_management,
                LoadVaultKeysetForUser(obfuscated_username, index))
        .WillRepeatedly([=](const ObfuscatedUsername&, int) {
          auto vk = std::make_unique<VaultKeyset>();
          vk->InitializeFromSerialized(serialized_vk);
          return vk;
        });
  }
}

void MockKeysetLoadingByLabel(const ObfuscatedUsername& obfuscated_username,
                              const SerializedVaultKeyset& serialized_vk,
                              MockKeysetManagement& keyset_management) {
  EXPECT_CALL(
      keyset_management,
      GetVaultKeyset(obfuscated_username, serialized_vk.key_data().label()))
      .WillRepeatedly([=](const ObfuscatedUsername&, const std::string&) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->InitializeFromSerialized(serialized_vk);
        return vk;
      });
}

void MockKeysetDerivation(const ObfuscatedUsername& obfuscated_username,
                          const SerializedVaultKeyset& serialized_vk,
                          CryptoError derivation_error,
                          MockAuthBlockUtility& auth_block_utility) {
  // Return an arbitrary auth block type from the mock.
  EXPECT_CALL(auth_block_utility, GetAuthBlockTypeFromState(_))
      .WillOnce(Return(AuthBlockType::kTpmEcc));

  const CryptohomeError::ErrorLocationPair fake_error_location =
      CryptohomeError::ErrorLocationPair(
          static_cast<CryptohomeError::ErrorLocation>(1),
          std::string("FakeErrorLocation"));

  EXPECT_CALL(auth_block_utility, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
      .WillOnce([=](AuthBlockType, const AuthInput&, const AuthBlockState&,
                    AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(derivation_error == CryptoError::CE_NONE
                     ? OkStatus<CryptohomeCryptoError>()
                     : MakeStatus<CryptohomeCryptoError>(
                           fake_error_location, error::ErrorActionSet(),
                           derivation_error),
                 std::make_unique<KeyBlobs>(), std::nullopt);
      });
}

void MockKeysetLoadingViaBlobs(const ObfuscatedUsername& obfuscated_username,
                               const SerializedVaultKeyset& serialized_vk,
                               MockKeysetManagement& keyset_management) {
  EXPECT_CALL(keyset_management, GetValidKeyset(obfuscated_username, _, _))
      .WillOnce([=](const ObfuscatedUsername&, KeyBlobs,
                    const std::optional<std::string>&) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->InitializeFromSerialized(serialized_vk);
        return vk;
      });
}

void MockOwnerUser(const std::string& username, MockHomeDirs& homedirs) {
  EXPECT_CALL(homedirs, GetPlainOwner(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(Username(username)), Return(true)));
}

}  // namespace

class AuthSessionInterfaceTestBase : public ::testing::Test {
 public:
  AuthSessionInterfaceTestBase()
      : crypto_(&hwsec_, &pinweaver_, &cryptohome_keys_manager_, nullptr) {
    SetUpHWSecExpectations();
    MockLECredentialManager* le_cred_manager = new MockLECredentialManager();
    crypto_.set_le_manager_for_testing(
        std::unique_ptr<LECredentialManager>(le_cred_manager));
    crypto_.Init();

    userdataauth_.set_platform(&platform_);
    userdataauth_.set_homedirs(&homedirs_);
    userdataauth_.set_user_session_factory(&user_session_factory_);
    userdataauth_.set_keyset_management(&keyset_management_);
    userdataauth_.set_auth_factor_driver_manager_for_testing(
        &auth_factor_driver_manager_);
    userdataauth_.set_auth_factor_manager_for_testing(&auth_factor_manager_);
    userdataauth_.set_user_secret_stash_storage_for_testing(
        &user_secret_stash_storage_);
    userdataauth_.set_user_session_map_for_testing(&user_session_map_);
    userdataauth_.set_pkcs11_token_factory(&pkcs11_token_factory_);
    userdataauth_.set_user_activity_timestamp_manager(
        &user_activity_timestamp_manager_);
    userdataauth_.set_install_attrs(&install_attrs_);
    userdataauth_.set_mount_task_runner(
        task_environment.GetMainThreadTaskRunner());
    userdataauth_.set_pinweaver(&pinweaver_);
    // TODO(hardikgoyal): Rewrite tests to work with USS.
    features_.SetDefaultForFeature(Features::kUSSMigration, false);
  }

  void SetUpHWSecExpectations() {
    EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsSealingSupported()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, GetManufacturer())
        .WillRepeatedly(ReturnValue(0x43524f53));
    EXPECT_CALL(hwsec_, GetAuthValue(_, _))
        .WillRepeatedly(ReturnValue(brillo::SecureBlob()));
    EXPECT_CALL(hwsec_, SealWithCurrentUser(_, _, _))
        .WillRepeatedly(ReturnValue(brillo::Blob()));
    EXPECT_CALL(hwsec_, GetPubkeyHash(_))
        .WillRepeatedly(ReturnValue(brillo::Blob()));
    EXPECT_CALL(pinweaver_, IsEnabled()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(pinweaver_, GetVersion()).WillRepeatedly(ReturnValue(2));
    EXPECT_CALL(pinweaver_, BlockGeneratePk())
        .WillRepeatedly(ReturnOk<TPMError>());
  }

  void CreateAuthSessionManager(AuthBlockUtility* auth_block_utility) {
    auth_session_manager_ = std::make_unique<AuthSessionManager>(
        &crypto_, &platform_, &user_session_map_, &keyset_management_,
        auth_block_utility, &auth_factor_driver_manager_, &auth_factor_manager_,
        &user_secret_stash_storage_, &user_metadata_reader_);
    auth_session_manager_->set_features(&features_.async);
    userdataauth_.set_auth_session_manager(auth_session_manager_.get());
  }

 protected:
  const Username kUsername{"foo@example.com"};
  const Username kUsername2{"foo2@example.com"};
  const Username kUsername3{"foo3@example.com"};

  TaskEnvironment task_environment{
      TaskEnvironment::TimeSource::MOCK_TIME,
      TaskEnvironment::ThreadPoolExecutionMode::QUEUED};
  NiceMock<MockPlatform> platform_;
  UserSessionMap user_session_map_;
  NiceMock<MockHomeDirs> homedirs_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;
  Crypto crypto_;
  NiceMock<MockUserSessionFactory> user_session_factory_;
  std::unique_ptr<FingerprintAuthBlockService> fp_service_{
      FingerprintAuthBlockService::MakeNullService()};
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
  NiceMock<MockKeysetManagement> keyset_management_;
  NiceMock<MockPkcs11TokenFactory> pkcs11_token_factory_;
  NiceMock<MockUserOldestActivityTimestampManager>
      user_activity_timestamp_manager_;
  NiceMock<MockInstallAttributes> install_attrs_;
  std::unique_ptr<AuthSessionManager> auth_session_manager_;
  UserDataAuth userdataauth_;

  // Accessors functions to avoid making each test a friend.

  CryptohomeStatus PrepareGuestVaultImpl() {
    return userdataauth_.PrepareGuestVaultImpl();
  }

  CryptohomeStatus PrepareEphemeralVaultImpl(
      const std::string& auth_session_id) {
    return userdataauth_.PrepareEphemeralVaultImpl(auth_session_id);
  }

  CryptohomeStatus PreparePersistentVaultImpl(
      const std::string& auth_session_id,
      const CryptohomeVault::Options& vault_options) {
    return userdataauth_.PreparePersistentVaultImpl(auth_session_id,
                                                    vault_options);
  }

  CryptohomeStatus CreatePersistentUserImpl(
      const std::string& auth_session_id) {
    return userdataauth_.CreatePersistentUserImpl(auth_session_id);
  }

  void AddAuthFactor(
      user_data_auth::AddAuthFactorRequest request,
      base::OnceCallback<void(const user_data_auth::AddAuthFactorReply&)>
          on_done) {
    userdataauth_.AddAuthFactor(request, std::move(on_done));
  }

  void AuthenticateAuthFactor(
      user_data_auth::AuthenticateAuthFactorRequest request,
      base::OnceCallback<
          void(const user_data_auth::AuthenticateAuthFactorReply&)> on_done) {
    userdataauth_.AuthenticateAuthFactor(request, std::move(on_done));
  }

  void GetAuthSessionStatusImpl(
      AuthSession* auth_session,
      user_data_auth::GetAuthSessionStatusReply& reply) {
    userdataauth_.GetAuthSessionStatusImpl(auth_session, reply);
  }

  FakeFeaturesForTesting features_;
};

class AuthSessionInterfaceTest : public AuthSessionInterfaceTestBase {
 protected:
  AuthSessionInterfaceTest() {
    auth_block_utility_impl_ = std::make_unique<AuthBlockUtilityImpl>(
        &keyset_management_, &crypto_, &platform_, &features_.async,
        AsyncInitPtr<ChallengeCredentialsHelper>(nullptr), nullptr,
        AsyncInitPtr<BiometricsAuthBlockService>(nullptr));
    CreateAuthSessionManager(auth_block_utility_impl_.get());
  }

  AuthorizationRequest CreateAuthorization(const std::string& secret) {
    AuthorizationRequest req;
    req.mutable_key()->set_secret(secret);
    req.mutable_key()->mutable_data()->set_label("test-label");
    req.mutable_key()->mutable_data()->set_type(KeyData::KEY_TYPE_PASSWORD);
    return req;
  }

  void ExpectAuth(const Username& username, const brillo::SecureBlob& secret) {
    auto vk = std::make_unique<VaultKeyset>();
    EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
        .WillOnce(Return(ByMove(std::move(vk))));
    ON_CALL(keyset_management_, UserExists(SanitizeUserName(username)))
        .WillByDefault(Return(true));
  }

  void ExpectVaultKeyset(int num_of_keysets) {
    // Assert parameter num_of_calls cannot be negative.
    DCHECK_GT(num_of_keysets, 0);

    // Setup expectations for GetVaultKeyset to return an initialized
    // VaultKeyset Construct the vault keyset with credentials for
    // AuthBlockType::kTpmNotBoundToPcrAuthBlockState.
    const brillo::SecureBlob blob16(16, 'A');
    brillo::SecureBlob passkey(20, 'A');
    brillo::SecureBlob system_salt_ =
        brillo::SecureBlob(*brillo::cryptohome::home::GetSystemSalt());

    SerializedVaultKeyset serialized;
    serialized.set_flags(SerializedVaultKeyset::LE_CREDENTIAL);
    serialized.set_salt(system_salt_.data(), system_salt_.size());
    serialized.set_le_chaps_iv(blob16.data(), blob16.size());
    serialized.set_le_label(0);
    serialized.set_le_fek_iv(blob16.data(), blob16.size());

    EXPECT_CALL(keyset_management_, GetVaultKeyset(_, _))
        .Times(num_of_keysets)
        .WillRepeatedly([=](const ObfuscatedUsername& obfuscated_username,
                            const std::string& key_label) {
          auto vk = std::make_unique<VaultKeyset>();
          vk->InitializeFromSerialized(serialized);
          return vk;
        });
  }

  std::unique_ptr<AuthBlockUtilityImpl> auth_block_utility_impl_;
};

namespace {

TEST_F(AuthSessionInterfaceTest,
       PrepareEphemeralVaultWithNonEphemeralAuthSession) {
  MockOwnerUser("whoever", homedirs_);
  std::string serialized_token;
  // Auth session is initially not authenticated for ephemeral users.
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    EXPECT_THAT(auth_session->status(),
                AuthStatus::kAuthStatusFurtherFactorRequired);
    serialized_token = auth_session->serialized_token();
  }

  // User authed and exists.
  auto user_session = std::make_unique<MockUserSession>();
  CryptohomeStatus status = PrepareEphemeralVaultImpl(serialized_token);
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

// Test if PreparePersistentVaultImpl can succeed with invalid authSession. It
// should not.
TEST_F(AuthSessionInterfaceTest, PreparePersistentVaultWithInvalidAuthSession) {
  // No auth session.
  CryptohomeStatus status =
      PreparePersistentVaultImpl(/*auth_session_id=*/"", /*vault_options=*/{});
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
}

// Test for checking if PreparePersistentVaultImpl will proceed when given the
// broadcast ID of a session.
TEST_F(AuthSessionInterfaceTest, PreparePersistentVaultWithBroadcastId) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_public_token();
  }

  CryptohomeStatus status = PreparePersistentVaultImpl(serialized_token, {});
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
}

// Test for checking if PreparePersistentVaultImpl will proceed with
// unauthenticated auth session.
TEST_F(AuthSessionInterfaceTest,
       PreparePersistentVaultWithUnAuthenticatedAuthSession) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  CryptohomeStatus status = PreparePersistentVaultImpl(serialized_token, {});
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

// Test for checking if PreparePersistentVaultImpl will proceed with
// ephemeral auth session.
TEST_F(AuthSessionInterfaceTest,
       PreparePersistentVaultWithEphemeralAuthSession) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER, AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  CryptohomeStatus status = PreparePersistentVaultImpl(serialized_token, {});
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

// Test to check if PreparePersistentVaultImpl will succeed if user is not
// created.
TEST_F(AuthSessionInterfaceTest, PreparePersistentVaultNoShadowDir) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    // Say that the user was created and the session is authenticated, without
    // actually creating the user.
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    serialized_token = auth_session->serialized_token();
  }

  // If no shadow homedir - we do not have a user.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(false));

  CryptohomeStatus status = PreparePersistentVaultImpl(serialized_token, {});

  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND);
}

// Test CreatePersistentUserImpl with invalid auth_session.
TEST_F(AuthSessionInterfaceTest, CreatePersistentUserInvalidAuthSession) {
  // No auth session.
  ASSERT_THAT(CreatePersistentUserImpl("")->local_legacy_error().value(),
              Eq(user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN));
}

// Test CreatePersistentUserImpl fails when a forbidden auth_session token
// (all-zeroes) is specified.
TEST_F(AuthSessionInterfaceTest,
       CreatePersistentUserInvalidAllZeroesAuthSession) {
  std::string all_zeroes_token;
  {
    // Setup. To avoid hardcoding the length of the string in the test, first
    // serialize an arbitrary token and then replace its contents with zeroes.
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    ASSERT_THAT(auth_session_status, IsOk());
    all_zeroes_token = std::string(
        auth_session_status.value()->serialized_token().length(), '\0');
  }
  // Test.
  CryptohomeStatus status = CreatePersistentUserImpl(all_zeroes_token);

  // Verify.
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
}

// Test CreatePersistentUserImpl with valid auth_session but user fails to
// create.
TEST_F(AuthSessionInterfaceTest, CreatePersistentUserFailedCreate) {
  EXPECT_CALL(homedirs_, CryptohomeExists(SanitizeUserName(kUsername)))
      .WillOnce(ReturnValue(false));

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillOnce(Return(false));
  EXPECT_CALL(homedirs_, Create(kUsername)).WillOnce(Return(false));
  auto status = CreatePersistentUserImpl(serialized_token);
  EXPECT_THAT(status, NotOk());
  ASSERT_THAT(status->local_legacy_error(),
              Eq(user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE));
}

// Test CreatePersistentUserImpl when Vault already exists.
TEST_F(AuthSessionInterfaceTest, CreatePersistentUserVaultExists) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  EXPECT_CALL(homedirs_, CryptohomeExists(SanitizeUserName(kUsername)))
      .WillOnce(ReturnValue(true));
  ASSERT_THAT(
      CreatePersistentUserImpl(serialized_token)->local_legacy_error().value(),
      Eq(user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY));
}

// Test CreatePersistentUserImpl with Ephemeral AuthSession.
TEST_F(AuthSessionInterfaceTest, CreatePersistentUserWithEphemeralAuthSession) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER, AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  ASSERT_THAT(
      CreatePersistentUserImpl(serialized_token)->local_legacy_error().value(),
      Eq(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

// Test CreatePersistentUserImpl with a session broadcast ID.
TEST_F(AuthSessionInterfaceTest, CreatePersistentUserWithBroadcastId) {
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, 0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_public_token();
  }

  ASSERT_THAT(
      CreatePersistentUserImpl(serialized_token)->local_legacy_error().value(),
      Eq(user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN));
}

TEST_F(AuthSessionInterfaceTest, GetAuthSessionStatus) {
  user_data_auth::GetAuthSessionStatusReply reply;
  CryptohomeStatusOr<InUseAuthSession> auth_session_status =
      auth_session_manager_->CreateAuthSession(kUsername, 0,
                                               AuthIntent::kDecrypt);
  EXPECT_THAT(auth_session_status, IsOk());
  AuthSession* auth_session = auth_session_status.value().Get();

  // First verify that auth is required is the status.
  GetAuthSessionStatusImpl(auth_session, reply);
  ASSERT_THAT(reply.status(),
              Eq(user_data_auth::AUTH_SESSION_STATUS_FURTHER_FACTOR_REQUIRED));

  // Then create the user which should authenticate the session.
  ASSERT_TRUE(auth_session->OnUserCreated().ok());
  GetAuthSessionStatusImpl(auth_session, reply);
  ASSERT_THAT(reply.status(),
              Eq(user_data_auth::AUTH_SESSION_STATUS_AUTHENTICATED));

  // Finally move time forward to time out the session.
  task_environment.FastForwardBy(auth_session->GetRemainingTime() * 2);
  GetAuthSessionStatusImpl(auth_session, reply);
  ASSERT_THAT(reply.status(),
              Eq(user_data_auth::AUTH_SESSION_STATUS_INVALID_AUTH_SESSION));
}

TEST_F(AuthSessionInterfaceTest, GetHibernateSecretUnauthenticatedTest) {
  CryptohomeStatusOr<InUseAuthSession> auth_session_status =
      auth_session_manager_->CreateAuthSession(kUsername, 0,
                                               AuthIntent::kDecrypt);
  EXPECT_THAT(auth_session_status, IsOk());
  AuthSession* auth_session = auth_session_status.value().Get();

  // Verify an unauthenticated session fails in producing a hibernate secret.
  user_data_auth::GetHibernateSecretRequest request;
  request.set_auth_session_id(auth_session->serialized_token());
  user_data_auth::GetHibernateSecretReply hs_reply =
      userdataauth_.GetHibernateSecret(request);
  ASSERT_NE(hs_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_FALSE(hs_reply.hibernate_secret().length());
}

}  // namespace

class AuthSessionInterfaceMockAuthTest : public AuthSessionInterfaceTestBase {
 protected:
  AuthSessionInterfaceMockAuthTest() {
    userdataauth_.set_auth_block_utility(&mock_auth_block_utility_);
    CreateAuthSessionManager(&mock_auth_block_utility_);
  }

  user_data_auth::AddAuthFactorReply AddAuthFactor(
      const user_data_auth::AddAuthFactorRequest& request) {
    TestFuture<user_data_auth::AddAuthFactorReply> reply_future;
    userdataauth_.AddAuthFactor(
        request,
        reply_future.GetCallback<const user_data_auth::AddAuthFactorReply&>());
    return reply_future.Get();
  }

  user_data_auth::AddAuthFactorReply AddPasswordAuthFactor(
      const AuthSession& auth_session,
      const std::string& auth_factor_label,
      const std::string& password) {
    user_data_auth::AddAuthFactorRequest add_request;
    add_request.set_auth_session_id(auth_session.serialized_token());
    user_data_auth::AuthFactor& request_factor =
        *add_request.mutable_auth_factor();
    request_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
    request_factor.set_label(auth_factor_label);
    request_factor.mutable_password_metadata();
    add_request.mutable_auth_input()->mutable_password_input()->set_secret(
        password);
    return AddAuthFactor(add_request);
  }

  user_data_auth::AuthenticateAuthFactorReply AuthenticateAuthFactor(
      const user_data_auth::AuthenticateAuthFactorRequest& request) {
    TestFuture<user_data_auth::AuthenticateAuthFactorReply> reply_future;
    userdataauth_.AuthenticateAuthFactor(
        request,
        reply_future
            .GetCallback<const user_data_auth::AuthenticateAuthFactorReply&>());
    return reply_future.Get();
  }

  user_data_auth::AuthenticateAuthFactorReply
  LegacyAuthenticatePasswordAuthFactor(const AuthSession& auth_session,
                                       const std::string& auth_factor_label,
                                       const std::string& password) {
    user_data_auth::AuthenticateAuthFactorRequest request;
    request.set_auth_session_id(auth_session.serialized_token());
    request.set_auth_factor_label(auth_factor_label);
    request.mutable_auth_input()->mutable_password_input()->set_secret(
        password);
    return AuthenticateAuthFactor(request);
  }

  user_data_auth::AuthenticateAuthFactorReply AuthenticatePasswordAuthFactor(
      const AuthSession& auth_session,
      const std::string& auth_factor_label,
      const std::string& password) {
    user_data_auth::AuthenticateAuthFactorRequest request;
    request.set_auth_session_id(auth_session.serialized_token());
    request.add_auth_factor_labels(auth_factor_label);
    request.mutable_auth_input()->mutable_password_input()->set_secret(
        password);
    return AuthenticateAuthFactor(request);
  }

  // Simulates a new user creation flow by running `CreatePersistentUser` and
  // `PreparePersistentVault`. Sets up all necessary mocks. Returns an
  // authenticated AuthSession, or null on failure.
  AuthSession* CreateAndPrepareUserVault() {
    EXPECT_CALL(keyset_management_, UserExists(SanitizeUserName(kUsername)))
        .WillRepeatedly(Return(false));

    std::string serialized_token;
    {
      CryptohomeStatusOr<InUseAuthSession> auth_session_status =
          auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                   AuthIntent::kDecrypt);
      EXPECT_THAT(auth_session_status, IsOk());
      AuthSession* auth_session = auth_session_status.value().Get();

      if (!auth_session)
        return nullptr;

      serialized_token = auth_session->serialized_token();
    }

    // Create the user.
    EXPECT_CALL(homedirs_, CryptohomeExists(SanitizeUserName(kUsername)))
        .WillOnce(ReturnValue(false));
    EXPECT_CALL(homedirs_, Create(kUsername)).WillOnce(Return(true));
    EXPECT_THAT(CreatePersistentUserImpl(serialized_token), IsOk());

    // Prepare the user vault. Use the real user session class to exercise
    // internal state transitions.
    EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
        .WillRepeatedly(Return(true));
    auto mount = base::MakeRefCounted<MockMount>();
    EXPECT_CALL(*mount, IsMounted())
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    auto user_session = std::make_unique<RealUserSession>(
        kUsername, &homedirs_, &keyset_management_,
        &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
    EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
        .WillOnce(Return(ByMove(std::move(user_session))));
    EXPECT_THAT(PreparePersistentVaultImpl(serialized_token,
                                           /*vault_options=*/{}),
                IsOk());
    InUseAuthSession auth_session =
        auth_session_manager_->FindAuthSession(serialized_token);
    return auth_session.Get();
  }

  AuthSession* PrepareEphemeralUser() {
    std::string serialized_token;
    {
      CryptohomeStatusOr<InUseAuthSession> auth_session_status =
          auth_session_manager_->CreateAuthSession(
              kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER,
              AuthIntent::kDecrypt);
      EXPECT_THAT(auth_session_status, IsOk());
      AuthSession* auth_session = auth_session_status.value().Get();
      if (!auth_session)
        return nullptr;
      serialized_token = auth_session->serialized_token();
    }

    // Set up mocks for the user session creation. Use the real user session
    // class to exercise internal state transitions.
    auto mount = base::MakeRefCounted<MockMount>();
    EXPECT_CALL(*mount, IsMounted())
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mount, MountEphemeralCryptohome(kUsername))
        .WillOnce(ReturnOk<StorageError>());
    EXPECT_CALL(*mount, IsEphemeral()).WillRepeatedly(Return(true));
    auto user_session = std::make_unique<RealUserSession>(
        kUsername, &homedirs_, &keyset_management_,
        &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
    EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
        .WillOnce(Return(ByMove(std::move(user_session))));

    EXPECT_THAT(PrepareEphemeralVaultImpl(serialized_token), IsOk());
    InUseAuthSession auth_session =
        auth_session_manager_->FindAuthSession(serialized_token);
    return auth_session.Get();
  }

  FakeFeaturesForTesting features_;
  MockAuthBlockUtility mock_auth_block_utility_;
};

namespace {

TEST_F(AuthSessionInterfaceMockAuthTest, PrepareGuestVault) {
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, IsActive()).WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session, MountGuest()).WillOnce(Invoke([]() {
    return OkStatus<CryptohomeMountError>();
  }));
  EXPECT_CALL(user_session_factory_, New(_, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));
  EXPECT_THAT(PrepareGuestVaultImpl(), IsOk());

  // Trying to prepare another session should fail, whether it is guest, ...
  CryptohomeStatus status = PrepareGuestVaultImpl();
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_FATAL);

  // ... ephemeral, ...
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER, AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  status = PrepareEphemeralVaultImpl(serialized_token);
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);

  // ... or regular.
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername2);
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  EXPECT_CALL(homedirs_, Exists(obfuscated_username))
      .WillRepeatedly(Return(true));

  {
    CryptohomeStatusOr<InUseAuthSession> auth_session2_status =
        auth_session_manager_->CreateAuthSession(kUsername2, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session2_status, IsOk());
    AuthSession* auth_session2 = auth_session2_status.value().Get();
    ASSERT_TRUE(auth_session2);
    serialized_token = auth_session2->serialized_token();
  }

  user_data_auth::AuthenticateAuthFactorRequest auth_request2;
  auth_request2.set_auth_session_id(serialized_token);
  auth_request2.set_auth_factor_label(kPasswordLabel);
  auth_request2.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword2);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply2 =
      AuthenticateAuthFactor(auth_request2);
  ASSERT_EQ(auth_reply2.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(
      auth_reply2.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));
  status = PreparePersistentVaultImpl(serialized_token, {});
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);
}

TEST_F(AuthSessionInterfaceMockAuthTest, PrepareGuestVaultAfterFailedGuest) {
  auto user_session = std::make_unique<MockUserSession>();
  const CryptohomeError::ErrorLocationPair fake_error_location =
      CryptohomeError::ErrorLocationPair(
          static_cast<CryptohomeError::ErrorLocation>(1),
          std::string("FakeErrorLocation"));

  EXPECT_CALL(*user_session, IsActive()).WillRepeatedly(Return(false));
  EXPECT_CALL(*user_session, MountGuest()).WillOnce(Invoke([&]() {
    return MakeStatus<CryptohomeMountError>(
        fake_error_location,
        error::ErrorActionSet({error::PossibleAction::kReboot}),
        MOUNT_ERROR_FATAL, std::nullopt);
  }));

  auto user_session2 = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session2, IsActive()).WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session2, MountGuest()).WillOnce(Invoke([]() {
    return OkStatus<CryptohomeMountError>();
  }));

  EXPECT_CALL(user_session_factory_, New(_, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))))
      .WillOnce(Return(ByMove(std::move(user_session2))));

  // We set first invocation to fail, but the second should succeed.
  ASSERT_THAT(PrepareGuestVaultImpl(), NotOk());
  ASSERT_THAT(PrepareGuestVaultImpl(), IsOk());
}

TEST_F(AuthSessionInterfaceMockAuthTest,
       PrepareGuestVaultAfterFailedEphemeral) {
  // Auth session is initially not authenticated for ephemeral users.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER, AuthIntent::kDecrypt);
    EXPECT_TRUE(auth_session_status.ok());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
  }

  auto user_session = std::make_unique<MockUserSession>();
  const CryptohomeError::ErrorLocationPair fake_error_location =
      CryptohomeError::ErrorLocationPair(
          static_cast<CryptohomeError::ErrorLocation>(1),
          std::string("FakeErrorLocation"));
  EXPECT_CALL(*user_session, IsActive())
      .WillOnce(Return(false))
      .WillOnce(Return(false));
  EXPECT_CALL(*user_session, MountEphemeral(kUsername))
      .WillOnce(Invoke([&](const Username&) {
        return MakeStatus<CryptohomeMountError>(
            fake_error_location,
            error::ErrorActionSet({error::PossibleAction::kReboot}),
            MOUNT_ERROR_FATAL, std::nullopt);
      }));

  auto user_session2 = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session2, IsActive()).WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session2, MountGuest()).WillOnce(Invoke([]() {
    return OkStatus<CryptohomeMountError>();
  }));

  EXPECT_CALL(user_session_factory_, New(_, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))))
      .WillOnce(Return(ByMove(std::move(user_session2))));

  // We set first invocation to fail, but the second should succeed.
  ASSERT_THAT(PrepareEphemeralVaultImpl(serialized_token), NotOk());
  ASSERT_THAT(PrepareGuestVaultImpl(), IsOk());
}

TEST_F(AuthSessionInterfaceMockAuthTest,
       PrepareGuestVaultAfterFailedPersistent) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Authenticate the session.
  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  ASSERT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_VERIFY_ONLY, AUTH_INTENT_DECRYPT));

  // Arrange the vault operations.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, IsActive()).WillRepeatedly(Return(false));
  const CryptohomeError::ErrorLocationPair fake_error_location =
      CryptohomeError::ErrorLocationPair(
          static_cast<CryptohomeError::ErrorLocation>(1),
          std::string("FakeErrorLocation"));
  EXPECT_CALL(*user_session, MountVault(kUsername, _, _))
      .WillOnce(Invoke([&](const Username&, const FileSystemKeyset&,
                           const CryptohomeVault::Options&) {
        return MakeStatus<CryptohomeMountError>(
            fake_error_location,
            error::ErrorActionSet({error::PossibleAction::kReboot}),
            MOUNT_ERROR_FATAL, std::nullopt);
      }));
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));

  auto user_session2 = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session2, IsActive()).WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session2, MountGuest()).WillOnce(Invoke([]() {
    return OkStatus<CryptohomeMountError>();
  }));

  EXPECT_CALL(user_session_factory_, New(_, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))))
      .WillOnce(Return(ByMove(std::move(user_session2))));
  ASSERT_THAT(PreparePersistentVaultImpl(serialized_token, {}), NotOk());
  ASSERT_THAT(PrepareGuestVaultImpl(), IsOk());
}

TEST_F(AuthSessionInterfaceMockAuthTest, PrepareEphemeralVault) {
  MockOwnerUser("whoever", homedirs_);

  // No auth session.
  CryptohomeStatus status = PrepareEphemeralVaultImpl("");
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);

  // Auth session is initially not authenticated for ephemeral users.
  std::string serialized_token;
  std::string serialized_public_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER, AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    EXPECT_THAT(auth_session->status(),
                AuthStatus::kAuthStatusFurtherFactorRequired);
    serialized_token = auth_session->serialized_token();
    serialized_public_token = auth_session->serialized_public_token();
  }

  // Using the broadcast ID as the session ID should fail.
  status = PrepareEphemeralVaultImpl(serialized_public_token);
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);

  // User authed and exists.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, IsActive())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session, GetPkcs11Token()).WillRepeatedly(Return(nullptr));
  EXPECT_CALL(*user_session, IsEphemeral()).WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session, MountEphemeral(kUsername))
      .WillOnce(ReturnError<CryptohomeMountError>());
  EXPECT_CALL(user_session_factory_, New(_, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));

  EXPECT_THAT(PrepareEphemeralVaultImpl(serialized_token), IsOk());
  {
    InUseAuthSession auth_session =
        auth_session_manager_->FindAuthSession(serialized_token);
    EXPECT_THAT(auth_session->status(), AuthStatus::kAuthStatusAuthenticated);
    EXPECT_EQ(auth_session->GetRemainingTime().InSeconds(),
              time_left_after_authenticate);
  }

  // Set up expectation for add credential callback success.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  user_data_auth::AuthFactor& request_factor = *request.mutable_auth_factor();
  request_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request_factor.set_label(kPasswordLabel);
  request_factor.mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);

  user_data_auth::AddAuthFactorReply reply = AddAuthFactor(request);

  // Evaluate error returned by callback.
  ASSERT_THAT(reply.error(), Eq(user_data_auth::CRYPTOHOME_ERROR_NOT_SET));

  // Trying to mount again will yield busy.
  status = PrepareEphemeralVaultImpl(serialized_token);
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);

  // Guest fails if other sessions present.
  status = PrepareGuestVaultImpl();
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_FATAL);

  // And so does ephemeral
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session2_status =
        auth_session_manager_->CreateAuthSession(
            kUsername2, AUTH_SESSION_FLAGS_EPHEMERAL_USER,
            AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session2_status, IsOk());
    AuthSession* auth_session2 = auth_session2_status.value().Get();
    serialized_token = auth_session2->serialized_token();
  }
  status = PrepareEphemeralVaultImpl(serialized_token);
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);

  // But a different regular mount succeeds.
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername3);
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session3_status =
        auth_session_manager_->CreateAuthSession(kUsername3, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session3_status, IsOk());
    AuthSession* auth_session3 = auth_session3_status.value().Get();
    ASSERT_TRUE(auth_session3);
    serialized_token = auth_session3->serialized_token();
  }

  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword3);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  ASSERT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));

  auto user_session3 = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session3, IsActive())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session3, MountVault(kUsername3, _, _))
      .WillOnce(ReturnError<CryptohomeMountError>());
  EXPECT_CALL(user_session_factory_, New(_, _, _))
      .WillOnce(Return(ByMove(std::move(user_session3))));
  EXPECT_CALL(homedirs_, Exists(obfuscated_username))
      .WillRepeatedly(Return(true));

  EXPECT_THAT(PreparePersistentVaultImpl(serialized_token, {}), IsOk());
}

TEST_F(AuthSessionInterfaceMockAuthTest,
       PreparePersistentVaultAndThenGuestFail) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Authenticate the session.
  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  ASSERT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));

  // Arrange the vault operations.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, IsActive())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*user_session, MountVault(kUsername, _, _))
      .WillOnce(ReturnError<CryptohomeMountError>());
  EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));

  // User authed and exists.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));
  EXPECT_THAT(PreparePersistentVaultImpl(serialized_token, {}), IsOk());

  // Guest fails if other sessions present.
  auto status = PrepareGuestVaultImpl();
  EXPECT_THAT(status, NotOk());
  ASSERT_EQ(status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_FATAL);
}

TEST_F(AuthSessionInterfaceMockAuthTest,
       AuthenticateAuthFactorWithBroadcastId) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_public_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Verify
  ASSERT_EQ(reply.error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
  ASSERT_THAT(reply.authorized_for(), IsEmpty());
}

TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorNoLabel) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Verify
  ASSERT_NE(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(reply.authorized_for(), IsEmpty());
}

TEST_F(AuthSessionInterfaceMockAuthTest, GetHibernateSecretTest) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  ASSERT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));

  user_data_auth::GetHibernateSecretRequest hs_request;
  hs_request.set_auth_session_id(serialized_token);
  user_data_auth::GetHibernateSecretReply hs_reply =
      userdataauth_.GetHibernateSecret(hs_request);

  // Assert.
  EXPECT_EQ(hs_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_TRUE(hs_reply.hibernate_secret().length());
}

TEST_F(AuthSessionInterfaceMockAuthTest, GetHibernateSecretWithBroadcastId) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);

  std::string serialized_token;
  std::string serialized_public_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
    serialized_public_token = auth_session->serialized_public_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  ASSERT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));

  user_data_auth::GetHibernateSecretRequest hs_request;
  hs_request.set_auth_session_id(serialized_public_token);
  user_data_auth::GetHibernateSecretReply hs_reply =
      userdataauth_.GetHibernateSecret(hs_request);

  // Assert.
  EXPECT_EQ(hs_reply.error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
}

// Test that AuthenticateAuthFactor fails in case the VaultKeyset decryption
// failed.
TEST_F(AuthSessionInterfaceMockAuthTest,
       AuthenticateAuthFactorVkDecryptionError) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange. Mock VK decryption to return a failure.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk,
                       CryptoError::CE_OTHER_CRYPTO, mock_auth_block_utility_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor succeeds using credential verifier based
// lightweight authentication when `AuthIntent::kVerifyOnly` is requested.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorLightweight) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange. Set up a fake VK without authentication mocks.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  // Set up a user session with a mocked credential verifier.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, VerifyUser(SanitizeUserName(kUsername)))
      .WillOnce(Return(true));
  auto verifier = std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, kPasswordLabel,
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()});
  EXPECT_CALL(*verifier, VerifySync(_)).WillOnce(ReturnOk<CryptohomeError>());
  user_session->AddCredentialVerifier(std::move(verifier));
  EXPECT_TRUE(user_session_map_.Add(kUsername, std::move(user_session)));

  // Create an AuthSession.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kVerifyOnly);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert. The legacy `authenticated` field stays false.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(),
              UnorderedElementsAre(AUTH_INTENT_VERIFY_ONLY));
}

// Test that AuthenticateAuthFactor fails in case the AuthSession ID is missing.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorNoSessionId) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(false));

  // Act. Omit setting `auth_session_id` in the `request`.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails in case the AuthSession ID is invalid.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorBadSessionId) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(false));

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id("bad-session-id");
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails in case the AuthSession is expired.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorExpiredSession) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(false));
  std::string auth_session_id;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    auth_session_id = auth_session->serialized_token();
  }

  EXPECT_TRUE(auth_session_manager_->RemoveAuthSession(auth_session_id));

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(auth_session_id);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails in case the user doesn't exist.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorNoUser) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(false));
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);

    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails in case the user has no keys (because
// the user is just created). The AuthSession, however, stays authenticated.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorNoKeys) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(false));
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
    EXPECT_EQ(auth_session->status(), AuthStatus::kAuthStatusAuthenticated);
    EXPECT_EQ(auth_session->GetRemainingTime().InSeconds(),
              time_left_after_authenticate);
    EXPECT_THAT(
        auth_session->authorized_intents(),
        UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  EXPECT_THAT(
      reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails when a non-existing key label is
// specified.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorWrongVkLabel) {
  constexpr char kConfiguredKeyLabel[] = "fake-configured-label";
  constexpr char kRequestedKeyLabel[] = "fake-requested-label";
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kConfiguredKeyLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kRequestedKeyLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails when no AuthInput is provided.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorNoInput) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act. Omit setting `auth_input` in `request`.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test that AuthenticateAuthFactor fails when both |auth_factor_label| and
// |auth_factor_labels| are specified.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorLabelConflicts) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);

  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_TRUE(auth_session_status.ok());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  request.set_auth_factor_label(kPasswordLabel);
  request.add_auth_factor_labels(kPasswordLabel2);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  EXPECT_FALSE(reply.has_seconds_left());
  EXPECT_THAT(reply.authorized_for(), IsEmpty());
  EXPECT_EQ(userdataauth_.FindUserSessionForTest(kUsername), nullptr);
}

// Test the PreparePersistentVault, when called after a successful
// AuthenticateAuthFactor, mounts the home dir and sets up the user session.
TEST_F(AuthSessionInterfaceMockAuthTest, PrepareVaultAfterFactorAuthVk) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(Return(true));
  // Mock successful authentication via a VaultKeyset.
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  // Prepare an AuthSession.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Authenticate the AuthSession.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  EXPECT_EQ(AuthenticateAuthFactor(request).error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // Mock user vault mounting. Use the real user session class in order to check
  // session state transitions.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));
  auto mount = base::MakeRefCounted<MockMount>();
  EXPECT_CALL(*mount, IsMounted())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  auto user_session = std::make_unique<RealUserSession>(
      kUsername, &homedirs_, &keyset_management_,
      &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
  EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));

  // Act.
  CryptohomeStatus prepare_status =
      PreparePersistentVaultImpl(serialized_token, /*vault_options=*/{});

  // Assert.
  EXPECT_THAT(prepare_status, IsOk());
  UserSession* found_user_session =
      userdataauth_.FindUserSessionForTest(kUsername);
  ASSERT_TRUE(found_user_session);
  EXPECT_TRUE(found_user_session->IsActive());
  // Check the user session has a verifier for the given password.
  const CredentialVerifier* verifier =
      found_user_session->FindCredentialVerifier(kPasswordLabel);
  ASSERT_THAT(verifier, NotNull());
  AuthInput auth_input = {.user_input = brillo::SecureBlob(kPassword),
                          .obfuscated_username = obfuscated_username};
  EXPECT_TRUE(verifier->Verify(auth_input));
}

// Test the PreparePersistentVault, when called after a successful
// AuthenticateAuthFactor, mounts the home dir and sets up the user session.
// Following that, second call should fail.
TEST_F(AuthSessionInterfaceMockAuthTest,
       PrepareVaultAfterFactorAuthVkMountPointBusy) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(Return(true));
  // Mock successful authentication via a VaultKeyset.
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  // Prepare an AuthSession.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Authenticate the AuthSession.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  EXPECT_EQ(AuthenticateAuthFactor(request).error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // Mock user vault mounting. Use the real user session class in order to check
  // session state transitions.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));
  auto mount = base::MakeRefCounted<MockMount>();
  EXPECT_CALL(*mount, IsMounted())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  auto user_session = std::make_unique<RealUserSession>(
      kUsername, &homedirs_, &keyset_management_,
      &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
  EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));

  // Act.
  CryptohomeStatus prepare_status =
      PreparePersistentVaultImpl(serialized_token, /*vault_options=*/{});

  // Assert.
  EXPECT_THAT(prepare_status, IsOk());
  UserSession* found_user_session =
      userdataauth_.FindUserSessionForTest(kUsername);
  ASSERT_TRUE(found_user_session);
  EXPECT_TRUE(found_user_session->IsActive());

  // Trying to mount again will yield busy.
  prepare_status = PreparePersistentVaultImpl(serialized_token,
                                              /*vault_options=*/{});
  EXPECT_THAT(prepare_status, NotOk());
  ASSERT_EQ(prepare_status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);
}

// Test the PreparePersistentVault, when called after a successful
// AuthenticateAuthFactor, mounts the home dir and sets up the user session.
// Following that, a call to prepare ephemeral mount should fail.
TEST_F(AuthSessionInterfaceMockAuthTest, PreparePersistentVaultAndEphemeral) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(Return(true));
  // Mock successful authentication via a VaultKeyset.
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  // Prepare an AuthSession.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Authenticate the AuthSession.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  EXPECT_EQ(AuthenticateAuthFactor(request).error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // Mock user vault mounting. Use the real user session class in order to check
  // session state transitions.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));
  auto mount = base::MakeRefCounted<MockMount>();
  EXPECT_CALL(*mount, IsMounted())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  auto user_session = std::make_unique<RealUserSession>(
      kUsername, &homedirs_, &keyset_management_,
      &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
  EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));

  // Act.
  CryptohomeStatus prepare_status =
      PreparePersistentVaultImpl(serialized_token, /*vault_options=*/{});

  // Assert.
  EXPECT_THAT(prepare_status, IsOk());
  UserSession* found_user_session =
      userdataauth_.FindUserSessionForTest(kUsername);
  ASSERT_TRUE(found_user_session);
  EXPECT_TRUE(found_user_session->IsActive());

  // Trying to mount again will yield busy.
  prepare_status = PrepareEphemeralVaultImpl(serialized_token);
  EXPECT_THAT(prepare_status, NotOk());
  ASSERT_EQ(prepare_status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY);
}

// Test multi mount with two users.
TEST_F(AuthSessionInterfaceMockAuthTest, PreparePersistentVaultMultiMount) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(Return(true));
  // Mock successful authentication via a VaultKeyset.
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  // Prepare an AuthSession.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();

    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Authenticate the AuthSession.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  EXPECT_EQ(AuthenticateAuthFactor(request).error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // Mock user vault mounting. Use the real user session class in order to check
  // session state transitions.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername)))
      .WillRepeatedly(Return(true));
  auto mount = base::MakeRefCounted<MockMount>();
  EXPECT_CALL(*mount, IsMounted())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  auto user_session = std::make_unique<RealUserSession>(
      kUsername, &homedirs_, &keyset_management_,
      &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
  EXPECT_CALL(user_session_factory_, New(kUsername, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));

  // Act.
  CryptohomeStatus prepare_status =
      PreparePersistentVaultImpl(serialized_token, /*vault_options=*/{});

  // Assert.
  EXPECT_THAT(prepare_status, IsOk());

  // Try the second mount, it should succeed
  const ObfuscatedUsername obfuscated_username2 = SanitizeUserName(kUsername2);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username2))
      .WillRepeatedly(Return(true));
  // Mock successful authentication via a VaultKeyset.
  const SerializedVaultKeyset serialized_vk2 =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username2, {serialized_vk2},
                               keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username2, serialized_vk2,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username2, serialized_vk2,
                       CryptoError::CE_NONE, mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username2, serialized_vk2,
                            keyset_management_);
  // Prepare an AuthSession.
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status2 =
        auth_session_manager_->CreateAuthSession(kUsername2, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status2, IsOk());
    AuthSession* auth_session2 = auth_session_status2.value().Get();

    ASSERT_TRUE(auth_session2);
    serialized_token = auth_session2->serialized_token();
  }

  // Authenticate the AuthSession.
  user_data_auth::AuthenticateAuthFactorRequest request2;
  request2.set_auth_session_id(serialized_token);
  request2.set_auth_factor_label(kPasswordLabel);
  request2.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  EXPECT_EQ(AuthenticateAuthFactor(request2).error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // Mock user vault mounting. Use the real user session class in order to check
  // session state transitions.
  EXPECT_CALL(homedirs_, Exists(SanitizeUserName(kUsername2)))
      .WillRepeatedly(Return(true));
  mount = base::MakeRefCounted<MockMount>();
  EXPECT_CALL(*mount, IsMounted())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  user_session = std::make_unique<RealUserSession>(
      kUsername2, &homedirs_, &keyset_management_,
      &user_activity_timestamp_manager_, &pkcs11_token_factory_, mount);
  EXPECT_CALL(user_session_factory_, New(kUsername2, _, _))
      .WillOnce(Return(ByMove(std::move(user_session))));

  // Act.
  prepare_status = PreparePersistentVaultImpl(serialized_token,
                                              /*vault_options=*/{});

  // Assert.
  EXPECT_THAT(prepare_status, IsOk());
}

// That that AddAuthFactor succeeds for a freshly prepared ephemeral user. The
// credential is stored in the user session as a verifier.
TEST_F(AuthSessionInterfaceMockAuthTest,
       AddPasswordFactorAfterPrepareEphemeral) {
  // Arrange.
  // Pretend to have a different owner user, because otherwise the ephemeral
  // login is disallowed.
  MockOwnerUser("whoever", homedirs_);
  // Prepare the ephemeral vault, which should also create the session.
  AuthSession* const auth_session = PrepareEphemeralUser();
  ASSERT_TRUE(auth_session);
  UserSession* found_user_session =
      userdataauth_.FindUserSessionForTest(kUsername);
  ASSERT_TRUE(found_user_session);
  EXPECT_TRUE(found_user_session->IsActive());
  EXPECT_THAT(found_user_session->GetCredentialVerifiers(), IsEmpty());

  // Act.
  user_data_auth::AddAuthFactorReply reply =
      AddPasswordAuthFactor(*auth_session, kPasswordLabel, kPassword);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_TRUE(reply.has_added_auth_factor());
  EXPECT_EQ(reply.added_auth_factor().auth_factor().label(), kPasswordLabel);
  EXPECT_THAT(reply.added_auth_factor().available_for_intents(),
              UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY));
  EXPECT_TRUE(reply.added_auth_factor().auth_factor().has_password_metadata());
  // Check the user session has a verifier for the given password.
  const CredentialVerifier* verifier =
      found_user_session->FindCredentialVerifier(kPasswordLabel);
  ASSERT_THAT(verifier, NotNull());
  AuthInput auth_input = {.user_input = brillo::SecureBlob(kPassword),
                          .obfuscated_username = SanitizeUserName(kUsername)};
  EXPECT_TRUE(verifier->Verify(auth_input));
  EXPECT_THAT(
      auth_session->authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
}

// Test that AuthenticateAuthFactor succeeds for a freshly prepared ephemeral
// user who has a password added.
TEST_F(AuthSessionInterfaceMockAuthTest,
       AuthenticatePasswordFactorForEphemeral) {
  // Arrange.
  // Pretend to have a different owner user, because otherwise the ephemeral
  // login is disallowed.
  MockOwnerUser("whoever", homedirs_);
  AuthSession* const first_auth_session = PrepareEphemeralUser();
  ASSERT_TRUE(first_auth_session);
  user_data_auth::AddAuthFactorReply add_reply =
      AddPasswordAuthFactor(*first_auth_session, kPasswordLabel, kPassword);

  EXPECT_EQ(add_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_TRUE(add_reply.has_added_auth_factor());
  EXPECT_EQ(add_reply.added_auth_factor().auth_factor().label(),
            kPasswordLabel);
  EXPECT_THAT(add_reply.added_auth_factor().available_for_intents(),
              UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY));
  EXPECT_TRUE(
      add_reply.added_auth_factor().auth_factor().has_password_metadata());

  // Act.
  AuthSession* second_auth_session;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER,
            AuthIntent::kVerifyOnly);
    EXPECT_THAT(auth_session_status, IsOk());
    second_auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(second_auth_session);
  }

  user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticatePasswordAuthFactor(*second_auth_session, kPasswordLabel,
                                     kPassword);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(second_auth_session->authorized_intents(),
              UnorderedElementsAre(AuthIntent::kVerifyOnly));
}

// Test that AuthenticateAuthFactor succeeds for a freshly prepared ephemeral
// user who has a password added. Test the same functionality as
// AuthenticatePassworFactorForEphermeral. Use a different helper method to
// construct the request with legacy |auth_factor_label| to ensure backward
// compatibility.
TEST_F(AuthSessionInterfaceMockAuthTest,
       LegacyAuthenticatePasswordFactorForEphemeral) {
  // Arrange.
  // Pretend to have a different owner user, because otherwise the ephemeral
  // login is disallowed.
  MockOwnerUser("whoever", homedirs_);
  AuthSession* const first_auth_session = PrepareEphemeralUser();
  ASSERT_TRUE(first_auth_session);
  auto add_reply =
      AddPasswordAuthFactor(*first_auth_session, kPasswordLabel, kPassword);

  EXPECT_EQ(add_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_TRUE(add_reply.has_added_auth_factor());
  EXPECT_EQ(add_reply.added_auth_factor().auth_factor().label(),
            kPasswordLabel);
  EXPECT_THAT(add_reply.added_auth_factor().available_for_intents(),
              UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY));
  EXPECT_TRUE(
      add_reply.added_auth_factor().auth_factor().has_password_metadata());

  // Act.
  AuthSession* second_auth_session;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER,
            AuthIntent::kVerifyOnly);
    EXPECT_TRUE(auth_session_status.ok());
    second_auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(second_auth_session);
  }
  user_data_auth::AuthenticateAuthFactorReply reply =
      LegacyAuthenticatePasswordAuthFactor(*second_auth_session, kPasswordLabel,
                                           kPassword);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(second_auth_session->authorized_intents(),
              UnorderedElementsAre(AuthIntent::kVerifyOnly));
}

// Test that AuthenticateAuthFactor fails for a freshly prepared ephemeral user
// if a wrong password is provided.
TEST_F(AuthSessionInterfaceMockAuthTest,
       AuthenticatePasswordFactorForEphemeralWrongPassword) {
  // Arrange.
  // Pretend to have a different owner user, because otherwise the ephemeral
  // login is disallowed.
  MockOwnerUser("whoever", homedirs_);
  // Prepare the ephemeral user with a password configured.
  AuthSession* const first_auth_session = PrepareEphemeralUser();
  ASSERT_TRUE(first_auth_session);
  EXPECT_EQ(
      AddPasswordAuthFactor(*first_auth_session, kPasswordLabel, kPassword)
          .error(),
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Act.
  AuthSession* second_auth_session;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER,
            AuthIntent::kVerifyOnly);
    EXPECT_THAT(auth_session_status, IsOk());
    second_auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(second_auth_session);
  }
  user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticatePasswordAuthFactor(*second_auth_session, kPasswordLabel,
                                     kPassword2);

  // Assert.
  EXPECT_EQ(reply.error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  EXPECT_THAT(second_auth_session->authorized_intents(), IsEmpty());
}

// Test that AuthenticateAuthFactor fails for a freshly prepared ephemeral user
// if no password was configured.
TEST_F(AuthSessionInterfaceMockAuthTest,
       AuthenticatePasswordFactorForEphemeralNoPassword) {
  // Arrange.
  // Pretend to have a different owner user, because otherwise the ephemeral
  // login is disallowed.
  MockOwnerUser("whoever", homedirs_);
  // Prepare the ephemeral user without any factor configured.
  EXPECT_TRUE(PrepareEphemeralUser());

  // Act.
  AuthSession* auth_session;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(
            kUsername, AUTH_SESSION_FLAGS_EPHEMERAL_USER,
            AuthIntent::kVerifyOnly);
    EXPECT_THAT(auth_session_status, IsOk());
    auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
  }
  user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticatePasswordAuthFactor(*auth_session, kPasswordLabel, kPassword);

  // Assert. The error code is such because AuthSession falls back to checking
  // persistent auth factors.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  EXPECT_THAT(auth_session->authorized_intents(), IsEmpty());
}

// Test that RemoveAuthFactor successfully removes the VaultKeyset with the
// given label.
TEST_F(AuthSessionInterfaceMockAuthTest, RemoveAuthFactorVkSuccess) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  const SerializedVaultKeyset serialized_vk2 =
      CreateFakePasswordVk(kPasswordLabel2);
  // AuthSession first loads all KeyData mapped to labels.
  MockVKToAuthFactorMapLoading(
      obfuscated_username, {serialized_vk, serialized_vk2}, keyset_management_);

  // AuthenticateAuthFactor loads the VK to be authenticated.
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk2,
                           keyset_management_);
  // RemoveAuthFactor loads the VK to be removed.
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk2,
                       CryptoError::CE_NONE, mock_auth_block_utility_);
  // Decrypt loaded VK.
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk2,
                            keyset_management_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel2);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  EXPECT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));

  // Act.
  // Test that RemoveAuthFactor fails to remove the non-existing VK.
  user_data_auth::RemoveAuthFactorRequest remove_request;
  remove_request.set_auth_session_id(serialized_token);
  remove_request.set_auth_factor_label(kPasswordLabel);
  TestFuture<user_data_auth::RemoveAuthFactorReply> remove_reply_future;
  userdataauth_.RemoveAuthFactor(
      remove_request,
      remove_reply_future
          .GetCallback<const user_data_auth::RemoveAuthFactorReply&>());

  // Assert.
  EXPECT_EQ(remove_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
}

// Test that RemoveAuthFactor returns failure from remove request with the non
// existing label.
TEST_F(AuthSessionInterfaceMockAuthTest, RemoveAuthFactorVkFailsLastKeyset) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);

  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  EXPECT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));
  // Act.
  // Test that RemoveAuthFactor fails to remove the non-existing VK.
  user_data_auth::RemoveAuthFactorRequest remove_request;
  remove_request.set_auth_session_id(serialized_token);
  remove_request.set_auth_factor_label(kPasswordLabel2);
  TestFuture<user_data_auth::RemoveAuthFactorReply> remove_reply_future;
  userdataauth_.RemoveAuthFactor(
      remove_request,
      remove_reply_future
          .GetCallback<const user_data_auth::RemoveAuthFactorReply&>());

  // Assert.
  EXPECT_EQ(remove_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
}

// Test that RemoveAuthFactor fails to remove the only factor.
TEST_F(AuthSessionInterfaceMockAuthTest,
       RemoveAuthFactorVkFailsNonExitingLabel) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);

  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  EXPECT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));
  // Act.
  // Test that RemoveAuthFactor fails to remove the non-existing VK.
  user_data_auth::RemoveAuthFactorRequest remove_request;
  remove_request.set_auth_session_id(serialized_token);
  remove_request.set_auth_factor_label(kPasswordLabel);
  TestFuture<user_data_auth::RemoveAuthFactorReply> remove_reply_future;
  userdataauth_.RemoveAuthFactor(
      remove_request,
      remove_reply_future
          .GetCallback<const user_data_auth::RemoveAuthFactorReply&>());

  // Assert.
  EXPECT_EQ(remove_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_REMOVE_CREDENTIALS_FAILED);
}

// Test that RemoveAuthFactor fails to remove the authenticated VaultKeyset.
TEST_F(AuthSessionInterfaceMockAuthTest,
       RemoveAuthFactorVkFailsToRemoveSameVK) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  const SerializedVaultKeyset serialized_vk2 =
      CreateFakePasswordVk(kPasswordLabel2);
  // AuthSession first loads all KeyData mapped to labels.
  MockVKToAuthFactorMapLoading(
      obfuscated_username, {serialized_vk, serialized_vk2}, keyset_management_);

  // Creation loads every VK.
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk2,
                           keyset_management_);
  // AuthenticateAuthFactor loads the VK to be authenticated.
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  // RemoveAuthFactor loads the VK to be removed.
  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  // Decrypt loaded VK.
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kDecrypt);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(serialized_token);
  auth_request.set_auth_factor_label(kPasswordLabel);
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword);
  const user_data_auth::AuthenticateAuthFactorReply auth_reply =
      AuthenticateAuthFactor(auth_request);
  EXPECT_EQ(auth_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(
      auth_reply.authorized_for(),
      UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY));
  // Act.
  // Test that RemoveAuthFactor fails to remove the non-existing VK.
  user_data_auth::RemoveAuthFactorRequest remove_request;
  remove_request.set_auth_session_id(serialized_token);
  remove_request.set_auth_factor_label(kPasswordLabel);
  TestFuture<user_data_auth::RemoveAuthFactorReply> remove_reply_future;
  userdataauth_.RemoveAuthFactor(
      remove_request,
      remove_reply_future
          .GetCallback<const user_data_auth::RemoveAuthFactorReply&>());

  // Assert.
  EXPECT_EQ(remove_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_REMOVE_CREDENTIALS_FAILED);
}

// Test that AuthenticateAuthFactor succeeds for an existing user and a
// VautKeyset-based factor when using the correct credential, and that the
// WebAuthn secret is prepared when `AuthIntent::kWebAuthn` is requested.
TEST_F(AuthSessionInterfaceMockAuthTest, AuthenticateAuthFactorWebAuthnIntent) {
  const ObfuscatedUsername obfuscated_username = SanitizeUserName(kUsername);

  // Arrange.
  EXPECT_CALL(keyset_management_, UserExists(obfuscated_username))
      .WillRepeatedly(ReturnValue(true));
  const SerializedVaultKeyset serialized_vk =
      CreateFakePasswordVk(kPasswordLabel);
  MockVKToAuthFactorMapLoading(obfuscated_username, {serialized_vk},
                               keyset_management_);

  MockKeysetLoadingByLabel(obfuscated_username, serialized_vk,
                           keyset_management_);
  MockKeysetDerivation(obfuscated_username, serialized_vk, CryptoError::CE_NONE,
                       mock_auth_block_utility_);
  MockKeysetLoadingViaBlobs(obfuscated_username, serialized_vk,
                            keyset_management_);
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, PrepareWebAuthnSecret(_, _));
  EXPECT_TRUE(user_session_map_.Add(kUsername, std::move(user_session)));
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_->CreateAuthSession(kUsername, /*flags=*/0,
                                                 AuthIntent::kWebAuthn);
    EXPECT_THAT(auth_session_status, IsOk());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_TRUE(auth_session);
    serialized_token = auth_session->serialized_token();
  }

  // Act.
  user_data_auth::AuthenticateAuthFactorRequest request;
  request.set_auth_session_id(serialized_token);
  request.set_auth_factor_label(kPasswordLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(kPassword);
  const user_data_auth::AuthenticateAuthFactorReply reply =
      AuthenticateAuthFactor(request);

  // Assert.
  EXPECT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  InUseAuthSession auth_session =
      auth_session_manager_->FindAuthSession(serialized_token);
  EXPECT_EQ(auth_session->GetRemainingTime().InSeconds(),
            time_left_after_authenticate);
  EXPECT_THAT(reply.authorized_for(),
              UnorderedElementsAre(AUTH_INTENT_DECRYPT, AUTH_INTENT_VERIFY_ONLY,
                                   AUTH_INTENT_WEBAUTHN));
}

}  // namespace

}  // namespace cryptohome
