// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for AuthSession.

#include "cryptohome/auth_session.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback_helpers.h>
#include <base/run_loop.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/bind.h>
#include <base/test/power_monitor_test.h>
#include <base/test/simple_test_clock.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <base/timer/mock_timer.h>
#include <base/unguessable_token.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/auth_block_utility_impl.h"
#include "cryptohome/auth_blocks/biometrics_auth_block_service.h"
#include "cryptohome/auth_blocks/mock_auth_block_utility.h"
#include "cryptohome/auth_blocks/mock_biometrics_command_processor.h"
#include "cryptohome/auth_blocks/tpm_bound_to_pcr_auth_block.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/challenge_credentials/mock_challenge_credentials_helper.h"
#include "cryptohome/credential_verifier_test_utils.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/mock_credential_verifier.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_key_challenge_service_factory.h"
#include "cryptohome/mock_keyset_management.h"
#include "cryptohome/mock_le_credential_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/pkcs11/mock_pkcs11_token_factory.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mock_mount.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_secret_stash/user_metadata.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/user_session/mock_user_session.h"
#include "cryptohome/user_session/real_user_session.h"
#include "cryptohome/user_session/user_session_map.h"
#include "cryptohome/username.h"
#include "cryptohome/vault_keyset.pb.h"

namespace cryptohome {
namespace {

using base::test::TestFuture;
using brillo::cryptohome::home::SanitizeUserName;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::CryptohomeMountError;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;
using hwsec_foundation::error::testing::ReturnValue;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;
using ::testing::_;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Field;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::Matcher;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::Return;
using ::testing::UnorderedElementsAre;
using ::testing::VariantWith;

// Fake labels to be in used in this test suite.
constexpr char kFakeLabel[] = "test_label";
constexpr char kFakeOtherLabel[] = "test_other_label";
constexpr char kFakePinLabel[] = "test_pin_label";
constexpr char kLegacyLabel[] = "legacy-0";
constexpr char kRecoveryLabel[] = "recovery";
constexpr char kFakeFingerprintLabel[] = "test_fp_label";
constexpr char kFakeSecondFingerprintLabel[] = "test_second_fp_label";

// Fake passwords to be in used in this test suite.
constexpr char kFakePass[] = "test_pass";
constexpr char kFakePin[] = "123456";
constexpr char kFakeOtherPass[] = "test_other_pass";
constexpr char kFakeRecoverySecret[] = "test_recovery_secret";

// Fingerprint-related constants to be used in this test suite.
const uint64_t kFakeRateLimiterLabel = 100;
const uint64_t kFakeFpLabel = 200;
const uint64_t kFakeSecondFpLabel = 300;
constexpr char kFakeVkkKey[] = "fake_vkk_key";
constexpr char kFakeSecondVkkKey[] = "fake_second_vkk_key";
constexpr char kFakeRecordId[] = "fake_record_id";
constexpr char kFakeSecondRecordId[] = "fake_second_record_id";
constexpr char kFakeResetSecret[] = "fake_reset_secret";

// Set to match the 5 minute timer and a 1 minute extension in AuthSession.
constexpr int kAuthSessionExtensionDuration = 60;
// Upper limit of the Size of user specified name.
constexpr int kUserSpecifiedNameSizeLimit = 256;
constexpr auto kAuthSessionTimeout = base::Minutes(5);
constexpr base::TimeDelta kAuthFactorStatusUpdateDelay = base::Seconds(30);
constexpr auto kAuthSessionExtension =
    base::Seconds(kAuthSessionExtensionDuration);

// Returns a blob "derived" from provided blob to generate fake vkk_key from
// user secret in tests.
brillo::SecureBlob GetFakeDerivedSecret(const brillo::SecureBlob& blob) {
  return brillo::SecureBlob::Combine(blob,
                                     brillo::SecureBlob(" derived secret"));
}

// A matcher that checks if an auth block state has a particular type.
template <typename StateType>
Matcher<const AuthBlockState&> AuthBlockStateTypeIs() {
  return Field(&AuthBlockState::state, VariantWith<StateType>(_));
}

std::unique_ptr<VaultKeyset> CreatePasswordVaultKeyset(
    const std::string& label) {
  SerializedVaultKeyset serialized_vk;
  serialized_vk.set_flags(SerializedVaultKeyset::TPM_WRAPPED |
                          SerializedVaultKeyset::SCRYPT_DERIVED |
                          SerializedVaultKeyset::PCR_BOUND |
                          SerializedVaultKeyset::ECC);
  serialized_vk.set_password_rounds(1);
  serialized_vk.set_tpm_key("tpm-key");
  serialized_vk.set_extended_tpm_key("tpm-extended-key");
  serialized_vk.set_vkk_iv("iv");
  serialized_vk.mutable_key_data()->set_type(KeyData::KEY_TYPE_PASSWORD);
  serialized_vk.mutable_key_data()->set_label(label);
  auto vk = std::make_unique<VaultKeyset>();
  vk->InitializeFromSerialized(serialized_vk);
  return vk;
}

// A helpful utility for setting up AuthFactorMaps for testing. This provides a
// very concise way to construct them with a variety of configurable options.
// The way you use this is something like:
//
// auto auth_factor_map = AfMapBuilder().WithUss().AddPin("label").Consume();
//
// The end result of this will a map that contains a USS-backed PIN.
class AfMapBuilder {
 public:
  AfMapBuilder() = default;

  AfMapBuilder(const AfMapBuilder&) = delete;
  AfMapBuilder& operator=(const AfMapBuilder&) = delete;

  // Set the storage type of any subsequent factors.
  AfMapBuilder& WithVk() {
    storage_type_ = AuthFactorStorageType::kVaultKeyset;
    return *this;
  }
  AfMapBuilder& WithUss() {
    storage_type_ = AuthFactorStorageType::kUserSecretStash;
    return *this;
  }

  // Helpers to add different kinds of auth factors.
  template <typename StateType>
  AfMapBuilder& AddPassword(std::string label) {
    return AddFactor<StateType>(label, AuthFactorType::kPassword);
  }
  AfMapBuilder& AddPin(std::string label) {
    return AddFactor<PinWeaverAuthBlockState>(label, AuthFactorType::kPin);
  }
  AfMapBuilder& AddRecovery(std::string label) {
    return AddFactor<CryptohomeRecoveryAuthBlockState>(
        label, AuthFactorType::kCryptohomeRecovery);
  }

  // Helper to add copies of factors from an existing AuthFactorMap.
  AfMapBuilder& AddCopiesFromMap(const AuthFactorMap& af_map) {
    for (AuthFactorMap::ValueView entry : af_map) {
      map_.Add(std::make_unique<AuthFactor>(entry.auth_factor()),
               storage_type_);
    }
    return *this;
  }

  // Consume the map.
  AuthFactorMap Consume() { return std::move(map_); }

 private:
  // Generic add factor implementation. The template parameter specifies the
  // type of auth block state to use, or void for none.
  template <typename StateType>
  AfMapBuilder& AddFactor(std::string label, AuthFactorType auth_factor_type) {
    AuthBlockState auth_block_state;
    if constexpr (!std::is_void_v<StateType>) {
      auth_block_state.state = StateType();
    }
    map_.Add(
        std::make_unique<AuthFactor>(auth_factor_type, std::move(label),
                                     AuthFactorMetadata(), auth_block_state),
        storage_type_);
    return *this;
  }

  AuthFactorStorageType storage_type_ = AuthFactorStorageType::kVaultKeyset;

  AuthFactorMap map_;
};

}  // namespace

class AuthSessionTest : public ::testing::Test {
 public:
  AuthSessionTest() {
    auto mock_processor =
        std::make_unique<NiceMock<MockBiometricsCommandProcessor>>();
    bio_processor_ = mock_processor.get();
    bio_service_ = std::make_unique<BiometricsAuthBlockService>(
        std::move(mock_processor),
        /*enroll_signal_sender=*/base::DoNothing(),
        /*auth_signal_sender=*/base::DoNothing());
  }

  void SetUp() override {
    EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsSealingSupported()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, GetManufacturer())
        .WillRepeatedly(ReturnValue(0x43524f53));
    EXPECT_CALL(hwsec_, GetAuthValue(_, _))
        .WillRepeatedly(ReturnValue(brillo::SecureBlob()));
    EXPECT_CALL(hwsec_, SealWithCurrentUser(_, _, _))
        .WillRepeatedly(ReturnValue(brillo::Blob()));
    EXPECT_CALL(hwsec_, GetPubkeyHash(_))
        .WillRepeatedly(ReturnValue(brillo::Blob()));
    EXPECT_CALL(pinweaver_, IsEnabled()).WillRepeatedly(ReturnValue(true));
    crypto_.Init();
  }

 protected:
  // Fake username to be used in this test suite.
  const Username kFakeUsername{"test_username"};

  user_data_auth::CryptohomeErrorCode AuthenticateAuthFactorVK(
      const std::string& label,
      const std::string& passkey,
      AuthSession& auth_session) {
    // Used to mock out keyset factories with something that returns a
    // vanilla keyset with the supplied label.
    auto make_vk_with_label = [label](auto...) {
      auto vk = std::make_unique<VaultKeyset>();
      vk->SetKeyDataLabel(label);
      vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                   SerializedVaultKeyset::PCR_BOUND);
      TpmBoundToPcrAuthBlockState state;
      state.tpm_key = brillo::SecureBlob("");
      state.extended_tpm_key = brillo::SecureBlob("");
      vk->SetTpmBoundToPcrState(state);
      return vk;
    };

    EXPECT_CALL(keyset_management_, GetVaultKeyset(_, label))
        .WillRepeatedly(make_vk_with_label);
    EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
        .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
    EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
        .WillRepeatedly(make_vk_with_label);

    EXPECT_CALL(keyset_management_, ShouldReSaveKeyset(_))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(keyset_management_, AddResetSeedIfMissing(_))
        .WillRepeatedly(Return(false));

    EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
        .WillRepeatedly([](AuthBlockType auth_block_type,
                           const AuthInput& auth_input,
                           const AuthBlockState& auth_state,
                           AuthBlock::DeriveCallback derive_callback) {
          std::move(derive_callback)
              .Run(OkStatus<CryptohomeCryptoError>(),
                   std::make_unique<KeyBlobs>(), std::nullopt);
        });

    std::string auth_factor_labels[] = {label};
    user_data_auth::AuthInput auth_input_proto;
    auth_input_proto.mutable_password_input()->set_secret(passkey);

    TestFuture<CryptohomeStatus> authenticate_future;
    auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                        authenticate_future.GetCallback());

    if (authenticate_future.Get().ok()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }
    return authenticate_future.Get()->local_legacy_error().value();
  }

  // Get a UserSession for the given user, creating a minimal stub one if
  // necessary.
  UserSession* FindOrCreateUserSession(const Username& username) {
    if (UserSession* session = user_session_map_.Find(username)) {
      return session;
    }
    user_session_map_.Add(
        username, std::make_unique<RealUserSession>(
                      username, &homedirs_, &keyset_management_,
                      &user_activity_timestamp_manager_, &pkcs11_token_factory_,
                      new NiceMock<MockMount>()));
    return user_session_map_.Find(username);
  }

  base::test::ScopedPowerMonitorTestSource fake_power_monitor_source_;
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::SimpleTestClock clock_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_ =
      base::SequencedTaskRunner::GetCurrentDefault();

  // Mocks and fakes for the test AuthSessions to use.
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  Crypto crypto_{&hwsec_, &pinweaver_, &cryptohome_keys_manager_, nullptr};
  NiceMock<MockPlatform> platform_;
  UserSessionMap user_session_map_;
  NiceMock<MockKeysetManagement> keyset_management_;
  NiceMock<MockAuthBlockUtility> auth_block_utility_;
  std::unique_ptr<FingerprintAuthBlockService> fp_service_{
      FingerprintAuthBlockService::MakeNullService()};
  NiceMock<MockChallengeCredentialsHelper> challenge_credentials_helper_;
  NiceMock<MockKeyChallengeServiceFactory> key_challenge_service_factory_;
  NiceMock<MockBiometricsCommandProcessor>* bio_processor_;
  std::unique_ptr<BiometricsAuthBlockService> bio_service_;
  AuthFactorDriverManager auth_factor_driver_manager_{
      &platform_,
      &crypto_,
      AsyncInitPtr<ChallengeCredentialsHelper>(&challenge_credentials_helper_),
      &key_challenge_service_factory_,
      fp_service_.get(),
      AsyncInitPtr<BiometricsAuthBlockService>(base::BindRepeating(
          [](AuthSessionTest* test) { return test->bio_service_.get(); },
          base::Unretained(this))),
      nullptr};
  AuthFactorManager auth_factor_manager_{&platform_};
  FakeFeaturesForTesting fake_features_;
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
                                         &fake_features_.async};

  // Mocks and fakes for UserSession to use.
  HomeDirs homedirs_{&platform_,
                     std::make_unique<policy::PolicyProvider>(nullptr),
                     HomeDirs::RemoveCallback(),
                     /*vault_factory=*/nullptr};
  UserOldestActivityTimestampManager user_activity_timestamp_manager_{
      &platform_};
  NiceMock<MockPkcs11TokenFactory> pkcs11_token_factory_;
};

const CryptohomeError::ErrorLocationPair kErrorLocationForTestingAuthSession =
    CryptohomeError::ErrorLocationPair(
        static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
        std::string("MockErrorLocationAuthSession"));

TEST_F(AuthSessionTest, TokensAreValid) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_FALSE(auth_session.token().is_empty());
  EXPECT_FALSE(auth_session.public_token().is_empty());
  EXPECT_NE(auth_session.token(), auth_session.public_token());

  EXPECT_FALSE(auth_session.serialized_token().empty());
  EXPECT_FALSE(auth_session.serialized_public_token().empty());
  EXPECT_NE(auth_session.serialized_token(),
            auth_session.serialized_public_token());
}

TEST_F(AuthSessionTest, InitiallyNotAuthenticated) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());
}

TEST_F(AuthSessionTest, InitiallyNotAuthenticatedForExistingUser) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());
}

TEST_F(AuthSessionTest, Username) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_EQ(auth_session.username(), kFakeUsername);
  EXPECT_EQ(auth_session.obfuscated_username(),
            SanitizeUserName(kFakeUsername));
}

TEST_F(AuthSessionTest, DecryptionIntent) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_EQ(auth_session.auth_intent(), AuthIntent::kDecrypt);
}

TEST_F(AuthSessionTest, VerfyIntent) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_EQ(auth_session.auth_intent(), AuthIntent::kVerifyOnly);
}

TEST_F(AuthSessionTest, WebAuthnIntent) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kWebAuthn,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  EXPECT_EQ(auth_session.auth_intent(), AuthIntent::kWebAuthn);
}

// Test the scenario when `kCrOSLateBootMigrateToUserSecretStash` feature cannot
// be checked due to the feature lib unavailability. AuthSession should fall
// back to the default value (and not crash).
TEST_F(AuthSessionTest, UssMigrationFlagCheckFailure) {
  auto auth_session = AuthSession::Create(
      kFakeUsername, user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE,
      AuthIntent::kDecrypt, backing_apis_);

  // Verify.
  ASSERT_THAT(auth_session, NotNull());
  EXPECT_FALSE(auth_session->has_migrate_to_user_secret_stash());
}

TEST_F(AuthSessionTest, SerializedStringFromNullToken) {
  base::UnguessableToken token = base::UnguessableToken::Null();
  std::optional<std::string> serialized_token =
      AuthSession::GetSerializedStringFromToken(token);
  EXPECT_FALSE(serialized_token.has_value());
}

TEST_F(AuthSessionTest, TokenFromEmptyString) {
  std::string serialized_string = "";
  std::optional<base::UnguessableToken> unguessable_token =
      AuthSession::GetTokenFromSerializedString(serialized_string);
  EXPECT_FALSE(unguessable_token.has_value());
}

TEST_F(AuthSessionTest, TokenFromUnexpectedSize) {
  std::string serialized_string = "unexpected_sized_string";
  std::optional<base::UnguessableToken> unguessable_token =
      AuthSession::GetTokenFromSerializedString(serialized_string);
  EXPECT_FALSE(unguessable_token.has_value());
}

TEST_F(AuthSessionTest, TokenFromString) {
  base::UnguessableToken original_token = platform_.CreateUnguessableToken();
  std::optional<std::string> serialized_token =
      AuthSession::GetSerializedStringFromToken(original_token);
  EXPECT_TRUE(serialized_token.has_value());
  std::optional<base::UnguessableToken> deserialized_token =
      AuthSession::GetTokenFromSerializedString(serialized_token.value());
  EXPECT_TRUE(deserialized_token.has_value());
  EXPECT_EQ(deserialized_token.value(), original_token);
}

// Test that `GetSerializedStringFromToken()` refuses a string containing only
// zero bytes (but doesn't crash). Note: such a string would've corresponded to
// `base::UnguessableToken::Null()` if the latter would be allowed.
TEST_F(AuthSessionTest, TokenFromAllZeroesString) {
  // Setup. To avoid hardcoding the length of the string in the test, first
  // serialize an arbitrary token and then replace its contents with zeroes.
  const base::UnguessableToken some_token = base::UnguessableToken::Create();
  const std::optional<std::string> serialized_some_token =
      AuthSession::GetSerializedStringFromToken(some_token);
  ASSERT_TRUE(serialized_some_token.has_value());
  const std::string all_zeroes_token(serialized_some_token->length(), '\0');

  // Test.
  std::optional<base::UnguessableToken> deserialized_token =
      AuthSession::GetTokenFromSerializedString(all_zeroes_token);

  // Verify.
  EXPECT_EQ(deserialized_token, std::nullopt);
}

// Test that AuthenticateAuthFactor succeeds and doesn't use the credential
// verifier in the `AuthIntent::kDecrypt` scenario.
TEST_F(AuthSessionTest, NoLightweightAuthForDecryption) {
  // Add the user session. It will have no verifiers.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_TRUE(user_session_map_.Add(kFakeUsername, std::move(user_session)));

  // Create an AuthSession with a fake factor.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder().AddPassword<void>(kFakeLabel).Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  SetUserSecretStashExperimentForTesting(/*enabled=*/false);

  // Set up VaultKeyset authentication mock.
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeLabel))
      .WillRepeatedly([](auto...) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        TpmBoundToPcrAuthBlockState state;
        state.tpm_key = brillo::SecureBlob("");
        state.extended_tpm_key = brillo::SecureBlob("");
        vk->SetTpmBoundToPcrState(state);
        return vk;
      });
  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
      .WillOnce([](AuthBlockType, const AuthInput&, const AuthBlockState&,
                   AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(),
                 std::make_unique<KeyBlobs>(), std::nullopt);
      });
  EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
      .WillOnce([](const ObfuscatedUsername&, KeyBlobs,
                   const std::optional<std::string>& label) {
        KeyData key_data;
        key_data.set_label(*label);
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyData(std::move(key_data));
        return vk;
      });

  // Test.
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
}

// Test if AuthSession reports the correct attributes on an already-existing
// ephemeral user.
TEST_F(AuthSessionTest, ExistingEphemeralUser) {
  // Setup.
  int flags =
      user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_EPHEMERAL_USER;

  // Setting the expectation that there is no persistent user but there is an
  // active ephemeral one.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(false));
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, IsActive()).WillRepeatedly(Return(true));
  user_session_map_.Add(kFakeUsername, std::move(user_session));

  // Test.
  std::unique_ptr<AuthSession> auth_session = AuthSession::Create(
      kFakeUsername, flags, AuthIntent::kDecrypt, backing_apis_);

  // Verify.
  EXPECT_TRUE(auth_session->user_exists());
}

// Test that the UserSecretStash isn't created by default when a new user is
// created.
TEST_F(AuthSessionTest, NoUssByDefault) {
  // Setup.
  int flags = user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE;
  // Setting the expectation that the user does not exist.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(false));
  std::unique_ptr<AuthSession> auth_session = AuthSession::Create(
      kFakeUsername, flags, AuthIntent::kDecrypt, backing_apis_);

  // Test.
  EXPECT_FALSE(auth_session->has_user_secret_stash());
  EXPECT_TRUE(auth_session->OnUserCreated().ok());

  // Verify.
  EXPECT_FALSE(auth_session->has_user_secret_stash());
}

// Test if AuthenticateAuthFactor authenticates existing credentials for a
// user with VK.
TEST_F(AuthSessionTest, AuthenticateAuthFactorExistingVKUserNoResave) {
  // Setup AuthSession.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Test
  // Calling AuthenticateAuthFactor.
  EXPECT_EQ(AuthenticateAuthFactorVK(kFakeLabel, kFakePass, auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test if AuthenticateAuthFactor authenticates existing credentials for a
// user with VK and resaves it.
TEST_F(AuthSessionTest,
       AuthenticateAuthFactorExistingVKUserAndResaveForUpdate) {
  // Setup AuthSession.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .AddPassword<TpmNotBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Test
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeLabel))
      .WillRepeatedly([](auto...) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyDataLabel(kFakeLabel);
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED);
        TpmNotBoundToPcrAuthBlockState state;
        state.tpm_key = brillo::SecureBlob("");
        vk->SetTpmNotBoundToPcrState(state);
        return vk;
      });
  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kTpmNotBoundToPcr));
  EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
      .WillOnce([](const ObfuscatedUsername&, KeyBlobs,
                   const std::optional<std::string>& label) {
        KeyData key_data;
        key_data.set_label(*label);
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyData(std::move(key_data));
        return vk;
      });

  EXPECT_CALL(keyset_management_, ShouldReSaveKeyset(_)).WillOnce(Return(true));
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillOnce(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(keyset_management_, ReSaveKeyset(_, _, _));

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto auth_block_state2 = std::make_unique<AuthBlockState>();
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillOnce([&key_blobs, &auth_block_state2](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    AuthBlock::CreateCallback create_callback) {
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state2));
      });

  auto key_blobs2 = std::make_unique<KeyBlobs>();
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
      .WillOnce([&key_blobs2](AuthBlockType auth_block_type,
                              const AuthInput& auth_input,
                              const AuthBlockState& auth_state,
                              AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs2),
                 std::nullopt);
      });

  // Calling AuthenticateAuthFactor.
  TestFuture<CryptohomeStatus> authenticate_future;
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test if AuthenticateAuthFactor authenticates existing credentials for a
// user with VK and resaves it.
TEST_F(AuthSessionTest,
       AuthenticateAuthFactorExistingVKUserAndResaveForResetSeed) {
  // Setup AuthSession.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .AddPassword<TpmNotBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Test
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeLabel))
      .WillRepeatedly([](auto...) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyDataLabel(kFakeLabel);
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED);
        TpmNotBoundToPcrAuthBlockState state;
        state.tpm_key = brillo::SecureBlob("");
        vk->SetTpmNotBoundToPcrState(state);
        return vk;
      });
  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kTpmNotBoundToPcr));
  EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
      .WillOnce([](const ObfuscatedUsername&, KeyBlobs,
                   const std::optional<std::string>& label) {
        KeyData key_data;
        key_data.set_label(*label);
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyData(std::move(key_data));
        return vk;
      });

  EXPECT_CALL(keyset_management_, ShouldReSaveKeyset(_))
      .WillOnce(Return(false));
  EXPECT_CALL(keyset_management_, AddResetSeedIfMissing(_))
      .WillOnce(Return(true));
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillOnce(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(keyset_management_, ReSaveKeyset(_, _, _));

  auto key_blobs = std::make_unique<KeyBlobs>();
  auto auth_block_state2 = std::make_unique<AuthBlockState>();
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillOnce([&key_blobs, &auth_block_state2](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    AuthBlock::CreateCallback create_callback) {
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state2));
      });

  auto key_blobs2 = std::make_unique<KeyBlobs>();
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
      .WillOnce([&key_blobs2](AuthBlockType auth_block_type,
                              const AuthInput& auth_input,
                              const AuthBlockState& auth_state,
                              AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs2),
                 std::nullopt);
      });

  // Calling AuthenticateAuthFactor.
  TestFuture<CryptohomeStatus> authenticate_future;
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test that AuthenticateAuthFactor doesn't add reset seed to LECredentials.
TEST_F(AuthSessionTest,
       AuthenticateAuthFactorNotAddingResetSeedToPINVaultKeyset) {
  // Setup AuthSession.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AfMapBuilder().AddPin(kFakePinLabel).Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Test
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakePinLabel))
      .WillRepeatedly([](auto...) {
        auto vk = std::make_unique<VaultKeyset>();
        KeyData key_data;
        key_data.set_label(kFakePinLabel);
        key_data.mutable_policy()->set_low_entropy_credential(true);
        vk->SetKeyData(key_data);
        vk->SetFlags(SerializedVaultKeyset::LE_CREDENTIAL);
        PinWeaverAuthBlockState state;
        state.le_label = 0x12345678;
        vk->SetPinWeaverState(state);
        return vk;
      });
  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kPinWeaver));
  EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
      .WillOnce([](const ObfuscatedUsername&, KeyBlobs,
                   const std::optional<std::string>& label) {
        KeyData key_data;
        key_data.set_label(*label);
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyData(std::move(key_data));
        return vk;
      });

  EXPECT_CALL(keyset_management_, ShouldReSaveKeyset(_))
      .WillOnce(Return(false));
  EXPECT_CALL(keyset_management_, AddResetSeedIfMissing(_))
      .WillOnce(Return(false));

  auto key_blobs2 = std::make_unique<KeyBlobs>();
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
      .WillOnce([&key_blobs2](AuthBlockType auth_block_type,
                              const AuthInput& auth_input,
                              const AuthBlockState& auth_state,
                              AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs2),
                 std::nullopt);
      });

  // Calling AuthenticateAuthFactor.
  TestFuture<CryptohomeStatus> authenticate_future;
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_pin_input()->set_secret(kFakePin);
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
}

// Test that AuthenticateAuthFactor returns an error when supplied label and
// type mismatch.
TEST_F(AuthSessionTest, AuthenticateAuthFactorMismatchLabelAndType) {
  // Setup AuthSession.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AfMapBuilder().AddPin(kFakePinLabel).Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Test
  // Calling AuthenticateAuthFactor.
  TestFuture<CryptohomeStatus> authenticate_future;
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePin);
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  ASSERT_THAT(authenticate_future.Get(), NotOk());
  EXPECT_EQ(authenticate_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
}

// Test if AddAuthFactor correctly adds initial VaultKeyset password AuthFactor
// for a new user.
TEST_F(AuthSessionTest, AddAuthFactorNewUser) {
  // We need to use a real AuthBlockUtilityImpl for this test.
  FakeFeaturesForTesting features;
  AuthBlockUtilityImpl real_auth_block_utility(
      &keyset_management_, &crypto_, &platform_, &features.async,
      AsyncInitPtr<ChallengeCredentialsHelper>(nullptr), nullptr,
      AsyncInitPtr<BiometricsAuthBlockService>(nullptr));
  auto test_backing_apis = backing_apis_;
  test_backing_apis.auth_block_utility = &real_auth_block_utility;

  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      test_backing_apis);

  // Setting the expectation that the user does not exist.
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_FALSE(auth_session.user_exists());

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.user_exists());

  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  EXPECT_CALL(keyset_management_, AddInitialKeyset(_, _, _, _, _, _, _))
      .WillOnce(
          [](auto, auto, const KeyData& key_data, auto, auto, auto, auto) {
            auto vk = std::make_unique<VaultKeyset>();
            vk->SetKeyData(key_data);
            return vk;
          });
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeLabel))
      .WillOnce([](const ObfuscatedUsername&, const std::string&) {
        return CreatePasswordVaultKeyset(kFakeLabel);
      });

  // Test.
  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  EXPECT_THAT(add_future.Get(), IsOk());

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test that AddAuthFactor can add multiple VaultKeyset-AuthFactor. The first
// one is added as initial factor, the second is added as the second password
// factor, and the third one as added as a PIN factor.
TEST_F(AuthSessionTest, AddMultipleAuthFactor) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Setting the expectation that the user does not exist.
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_FALSE(auth_session.user_exists());

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.user_exists());

  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  // SelectAuthBlockTypeForCreation() and CreateKeyBlobsWithAuthBlock() are
  // called for each of the key addition operations below.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillRepeatedly([](AuthBlockType auth_block_type,
                         const AuthInput& auth_input,
                         AuthBlock::CreateCallback create_callback) {
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(),
                 std::make_unique<KeyBlobs>(),
                 std::make_unique<AuthBlockState>());
      });
  EXPECT_CALL(keyset_management_, AddInitialKeyset(_, _, _, _, _, _, _))
      .WillOnce(
          [](auto, auto, const KeyData& key_data, auto, auto, auto, auto) {
            auto vk = std::make_unique<VaultKeyset>();
            vk->SetKeyData(key_data);
            return vk;
          });
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, _))
      .WillRepeatedly([](const ObfuscatedUsername&, const std::string& label) {
        return CreatePasswordVaultKeyset(label);
      });

  // Test.
  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  EXPECT_THAT(add_future.Get(), IsOk());

  // Test adding new password AuthFactor
  user_data_auth::AddAuthFactorRequest request2;
  request2.set_auth_session_id(auth_session.serialized_token());
  request2.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request2.mutable_auth_factor()->set_label(kFakeOtherLabel);
  request2.mutable_auth_factor()->mutable_password_metadata();
  request2.mutable_auth_input()->mutable_password_input()->set_secret(
      kFakeOtherPass);

  EXPECT_CALL(keyset_management_, AddKeyset(_, _, _, _, _, _, _, _));

  // Test.
  TestFuture<CryptohomeStatus> add_future2;
  auth_session.AddAuthFactor(request2, add_future2.GetCallback());

  // Verify.
  ASSERT_THAT(add_future2.Get(), IsOk());
  // There should be credential verifiers for both passwords.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(
      user_session->GetCredentialVerifiers(),
      UnorderedElementsAre(
          IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass),
          IsVerifierPtrWithLabelAndPassword(kFakeOtherLabel, kFakeOtherPass)));

  // TODO(b:223222440) Add test to for adding a PIN after reset secret
  // generation function is updated.
}

// Test that AddAuthFactor succeeds for an ephemeral user and creates a
// credential verifier.
TEST_F(AuthSessionTest, AddPasswordFactorToEphemeral) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = true,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

  // Test.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  user_data_auth::AuthFactor& request_factor = *request.mutable_auth_factor();
  request_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request_factor.set_label(kFakeLabel);
  request_factor.mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  EXPECT_THAT(add_future.Get(), IsOk());

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test that AddAuthFactor fails for an ephemeral user when PIN is added.
TEST_F(AuthSessionTest, AddPinFactorToEphemeralFails) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = true,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

  // Test.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  user_data_auth::AuthFactor& request_factor = *request.mutable_auth_factor();
  request_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  request_factor.set_label(kFakePinLabel);
  request_factor.mutable_pin_metadata();
  request.mutable_auth_input()->mutable_pin_input()->set_secret(kFakePin);

  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  ASSERT_THAT(add_future.Get(), NotOk());
  EXPECT_EQ(add_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
}

TEST_F(AuthSessionTest, AddSecondPasswordFactorToEphemeral) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = true,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  // Add the first password.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  user_data_auth::AuthFactor& request_factor = *request.mutable_auth_factor();
  request_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request_factor.set_label(kFakeLabel);
  request_factor.mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);
  TestFuture<CryptohomeStatus> first_add_future;
  auth_session.AddAuthFactor(request, first_add_future.GetCallback());
  EXPECT_THAT(first_add_future.Get(), IsOk());

  // Test.
  request_factor.set_label(kFakeOtherLabel);
  request.mutable_auth_input()->mutable_password_input()->set_secret(
      kFakeOtherPass);
  TestFuture<CryptohomeStatus> second_add_future;
  auth_session.AddAuthFactor(request, second_add_future.GetCallback());

  // Verify.
  ASSERT_THAT(second_add_future.Get(), IsOk());
  // There should be two verifiers.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(
      user_session->GetCredentialVerifiers(),
      UnorderedElementsAre(
          IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass),
          IsVerifierPtrWithLabelAndPassword(kFakeOtherLabel, kFakeOtherPass)));
}

// UpdateAuthFactor request success when updating authenticated password VK.
TEST_F(AuthSessionTest, UpdateAuthFactorSucceedsForPasswordVK) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  AuthBlockState auth_block_state = auth_session.auth_factor_map()
                                        .Find(kFakeLabel)
                                        ->auth_factor()
                                        .auth_block_state();
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_TRUE(auth_session.user_exists());

  // SelectAuthBlockTypeForCreation() and CreateKeyBlobsWithAuthBlock() are
  // called for the key update operations below.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillRepeatedly([&](AuthBlockType auth_block_type,
                          const AuthInput& auth_input,
                          AuthBlock::CreateCallback create_callback) {
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(),
                 std::make_unique<KeyBlobs>(),
                 std::make_unique<AuthBlockState>(auth_block_state));
      });
  EXPECT_CALL(keyset_management_, UpdateKeysetWithKeyBlobs(_, _, _, _, _, _));

  // Set a valid |vault_keyset_| to update.
  KeyData key_data;
  key_data.set_label(kFakeLabel);
  auto vk = std::make_unique<VaultKeyset>();
  vk->Initialize(&platform_, &crypto_);
  vk->SetKeyData(key_data);
  vk->CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  vk->SetAuthBlockState(auth_block_state);
  auth_session.set_vault_keyset_for_testing(std::move(vk));

  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(request, update_future.GetCallback());

  // Verify.
  ASSERT_THAT(update_future.Get(), IsOk());

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// UpdateAuthFactor fails if label doesn't exist.
TEST_F(AuthSessionTest, UpdateAuthFactorFailsLabelNotMatchForVK) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_TRUE(auth_session.user_exists());

  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeOtherLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(
      kFakeOtherPass);

  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(request, update_future.GetCallback());

  // Verify.
  ASSERT_THAT(update_future.Get(), NotOk());
  // Verify that the credential_verifier is not updated on failure.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
}

// UpdateAuthFactor fails if label doesn't exist in the existing keysets.
TEST_F(AuthSessionTest, UpdateAuthFactorFailsLabelNotFoundForVK) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_THAT(AuthStatus::kAuthStatusFurtherFactorRequired,
              auth_session.status());
  EXPECT_TRUE(auth_session.user_exists());

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_TRUE(auth_session.user_exists());

  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeOtherLabel);
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeOtherLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(
      kFakeOtherPass);

  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(request, update_future.GetCallback());

  // Verify.
  ASSERT_THAT(update_future.Get(), NotOk());
  // Verify that the credential_verifier is not updated on failure.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
}

TEST_F(AuthSessionTest, TimeoutTest) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  TestFuture<base::UnguessableToken> timeout_future;
  auth_session.SetOnTimeoutCallback(
      timeout_future.GetCallback<const base::UnguessableToken&>());
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_EQ(auth_session.GetRemainingTime(), kAuthSessionTimeout);
  EXPECT_FALSE(timeout_future.IsReady());

  task_environment_.FastForwardBy(kAuthSessionTimeout);

  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusTimedOut);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());
  EXPECT_TRUE(timeout_future.IsReady());
  EXPECT_EQ(timeout_future.Get(), auth_session.token());
}

TEST_F(AuthSessionTest, TimeoutTestCallbackAfterTimeout) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_EQ(auth_session.GetRemainingTime(), kAuthSessionTimeout);

  task_environment_.FastForwardBy(kAuthSessionTimeout);

  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusTimedOut);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());

  TestFuture<base::UnguessableToken> timeout_future;
  auth_session.SetOnTimeoutCallback(
      timeout_future.GetCallback<const base::UnguessableToken&>());
  EXPECT_TRUE(timeout_future.IsReady());
  EXPECT_EQ(timeout_future.Get(), auth_session.token());
}

TEST_F(AuthSessionTest, TimeoutTestAfterPowerSuspend) {
  // Test.
  // Set up a WallClockTimer that will fire in one minute.
  std::unique_ptr<base::WallClockTimer> wall_clock_timer =
      std::make_unique<base::WallClockTimer>(
          &clock_, task_environment_.GetMockTickClock());

  clock_.SetNow(base::Time::Now());
  // AuthSession must be constructed without using AuthSessionManager,
  // because during cleanup the AuthSession must stay valid after
  // timing out for verification.
  AuthSession auth_session({.username = kFakeUsername,
                            .is_ephemeral_user = false,
                            .intent = AuthIntent::kDecrypt,
                            .timeout_timer = std::move(wall_clock_timer),
                            .auth_factor_status_update_timer =
                                std::make_unique<base::WallClockTimer>(),
                            .user_exists = false,
                            .auth_factor_map = AuthFactorMap(),
                            .migrate_to_user_secret_stash = false},
                           backing_apis_);
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_EQ(auth_session.GetRemainingTime(), kAuthSessionTimeout);

  // Have the device power off for 30 seconds
  constexpr auto time_passed = base::Seconds(30);
  fake_power_monitor_source_.Suspend();
  clock_.Advance(time_passed);
  task_environment_.FastForwardBy(time_passed);
  fake_power_monitor_source_.Resume();
  task_environment_.RunUntilIdle();

  EXPECT_EQ(auth_session.GetRemainingTime(), kAuthSessionTimeout - time_passed);
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);

  // Go forward the remaining lifetime (|kAuthSessionTimeout| - |time_passed|):
  clock_.Advance(kAuthSessionTimeout - time_passed);
  task_environment_.FastForwardBy(kAuthSessionTimeout - time_passed);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusTimedOut);
}

TEST_F(AuthSessionTest, ExtensionTest) {
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_EQ(auth_session.GetRemainingTime(), kAuthSessionTimeout);

  // Test.
  EXPECT_TRUE(auth_session.ExtendTimeoutTimer(kAuthSessionExtension).ok());

  // Verify that timer has changed, within a resaonsable degree of error.
  auto requested_delay = kAuthSessionTimeout + kAuthSessionExtension;
  EXPECT_EQ(auth_session.GetRemainingTime(), requested_delay);

  // Fast forward to end the lifetime of the AuthSession and check if properly
  // invalidates.
  task_environment_.FastForwardBy(requested_delay);
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusTimedOut);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());
}

// Test that AuthenticateAuthFactor succeeds in the `AuthIntent::kWebAuthn`
// scenario.
TEST_F(AuthSessionTest, AuthenticateAuthFactorWebAuthnIntent) {
  // Setup.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Add the user session. Expect that no verification calls are made.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, PrepareWebAuthnSecret(_, _));
  EXPECT_TRUE(user_session_map_.Add(kFakeUsername, std::move(user_session)));
  // Create an AuthSession with a fake factor.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kWebAuthn,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder().AddPassword<void>(kFakeLabel).Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Set up VaultKeyset authentication mock.
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeLabel))
      .WillRepeatedly([](auto...) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        TpmBoundToPcrAuthBlockState state;
        state.tpm_key = brillo::SecureBlob("");
        state.extended_tpm_key = brillo::SecureBlob("");
        vk->SetTpmBoundToPcrState(state);
        return vk;
      });
  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(_, _, _, _))
      .WillOnce([](AuthBlockType, const AuthInput&, const AuthBlockState&,
                   AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(),
                 std::make_unique<KeyBlobs>(), std::nullopt);
      });
  EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
      .WillOnce([](const ObfuscatedUsername&, KeyBlobs,
                   const std::optional<std::string>& label) {
        KeyData key_data;
        key_data.set_label(*label);
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyData(std::move(key_data));
        return vk;
      });

  // Test.
  TestFuture<CryptohomeStatus> authenticate_future;
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly,
                           AuthIntent::kWebAuthn));
}

// Test that AuthFactor map is updated after successful RemoveAuthFactor and
// not updated after unsuccessful RemoveAuthFactor.
TEST_F(AuthSessionTest, RemoveAuthFactorUpdatesAuthFactorMap) {
  // Setup.

  // Prepare the AuthFactor.
  AuthBlockState auth_block_state;
  auth_block_state.state = TpmBoundToPcrAuthBlockState();
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(
      std::make_unique<AuthFactor>(AuthFactorType::kPassword, kFakeLabel,
                                   AuthFactorMetadata(), auth_block_state),
      AuthFactorStorageType::kVaultKeyset);
  auth_factor_map.Add(
      std::make_unique<AuthFactor>(AuthFactorType::kPassword, kFakeOtherLabel,
                                   AuthFactorMetadata(), auth_block_state),
      AuthFactorStorageType::kVaultKeyset);

  // Create AuthSession.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_TRUE(auth_session.user_exists());

  EXPECT_EQ(AuthenticateAuthFactorVK(kFakeLabel, kFakePass, auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);

  // Test that RemoveAuthFactor success removes the factor from the map.
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeOtherLabel))
      .WillRepeatedly([](auto...) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetKeyDataLabel(kFakeOtherLabel);
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        TpmBoundToPcrAuthBlockState state;
        state.tpm_key = brillo::SecureBlob("");
        state.extended_tpm_key = brillo::SecureBlob("");
        vk->SetTpmBoundToPcrState(state);
        return vk;
      });
  user_data_auth::RemoveAuthFactorRequest remove_request;
  remove_request.set_auth_session_id(auth_session.serialized_token());
  remove_request.set_auth_factor_label(kFakeOtherLabel);
  TestFuture<CryptohomeStatus> remove_future;
  auth_session.RemoveAuthFactor(remove_request, remove_future.GetCallback());

  // Verify that AuthFactor is removed and the Authentication doesn't succeed
  // with the removed factor.
  ASSERT_THAT(remove_future.Get(), IsOk());
  EXPECT_EQ(AuthenticateAuthFactorVK(kFakeOtherLabel, kFakePass, auth_session),
            user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);

  // Test that RemoveAuthFactor failure doesn't remove the factor from the map.
  user_data_auth::RemoveAuthFactorRequest remove_request2;
  remove_request2.set_auth_session_id(auth_session.serialized_token());
  remove_request2.set_auth_factor_label(kFakeLabel);

  TestFuture<CryptohomeStatus> remove_future2;
  auth_session.RemoveAuthFactor(remove_request2, remove_future2.GetCallback());

  // Verify that AuthFactor is not removed and the Authentication doesn't
  // succeed with the removed factor.
  ASSERT_THAT(remove_future2.Get(), NotOk());
  EXPECT_EQ(remove_future2.Get()->local_legacy_error().value(),
            user_data_auth::CRYPTOHOME_REMOVE_CREDENTIALS_FAILED);
  EXPECT_EQ(AuthenticateAuthFactorVK(kFakeLabel, kFakePass, auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
}

// A variant of the auth session test that has the UserSecretStash experiment
// enabled.
class AuthSessionWithUssExperimentTest : public AuthSessionTest {
 protected:
  AuthSessionWithUssExperimentTest() {
    SetUserSecretStashExperimentForTesting(/*enabled=*/true);
  }

  ~AuthSessionWithUssExperimentTest() override {
    // Reset this global variable to avoid affecting unrelated test cases.
    SetUserSecretStashExperimentForTesting(/*enabled=*/std::nullopt);
  }

  struct ReplyToVerifyKey {
    void operator()(const Username& account_id,
                    const structure::ChallengePublicKeyInfo& public_key_info,
                    std::unique_ptr<KeyChallengeService> key_challenge_service,
                    ChallengeCredentialsHelper::VerifyKeyCallback callback) {
      if (is_key_valid) {
        std::move(callback).Run(OkStatus<error::CryptohomeCryptoError>());
      } else {
        const error::CryptohomeError::ErrorLocationPair
            kErrorLocationPlaceholder =
                error::CryptohomeError::ErrorLocationPair(
                    static_cast<
                        ::cryptohome::error::CryptohomeError::ErrorLocation>(1),
                    "Testing1");

        std::move(callback).Run(MakeStatus<error::CryptohomeCryptoError>(
            kErrorLocationPlaceholder,
            error::ErrorActionSet(error::PrimaryAction::kIncorrectAuth),
            CryptoError::CE_OTHER_CRYPTO));
      }
    }

    bool is_key_valid = false;
  };

  user_data_auth::CryptohomeErrorCode AddRecoveryAuthFactor(
      const std::string& label,
      const std::string& secret,
      AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
        .WillRepeatedly(ReturnValue(AuthBlockType::kCryptohomeRecovery));
    EXPECT_CALL(
        auth_block_utility_,
        CreateKeyBlobsWithAuthBlock(AuthBlockType::kCryptohomeRecovery, _, _))
        .WillOnce([&secret](auto auth_block_type, auto auth_input,
                            auto create_callback) {
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key = brillo::SecureBlob(secret);
          auto auth_block_state = std::make_unique<AuthBlockState>();
          auth_block_state->state = CryptohomeRecoveryAuthBlockState();
          std::move(create_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::move(auth_block_state));
        });
    // Prepare recovery add request.
    user_data_auth::AddAuthFactorRequest request;
    request.set_auth_session_id(auth_session.serialized_token());
    request.mutable_auth_factor()->set_type(
        user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY);
    request.mutable_auth_factor()->set_label(label);
    request.mutable_auth_factor()->mutable_cryptohome_recovery_metadata();
    request.mutable_auth_input()
        ->mutable_cryptohome_recovery_input()
        ->set_mediator_pub_key("mediator pub key");
    // Add recovery AuthFactor.
    TestFuture<CryptohomeStatus> add_future;
    auth_session.AddAuthFactor(request, add_future.GetCallback());

    if (add_future.Get().ok() ||
        !add_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }

    return add_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode AddPasswordAuthFactor(
      const std::string& label,
      const std::string& password,
      bool first_factor,
      AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
        .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
    EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(
                                         AuthBlockType::kTpmBoundToPcr, _, _))
        .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                     AuthBlock::CreateCallback create_callback) {
          // Make an arbitrary auth block state type can be used in this test.
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key =
              GetFakeDerivedSecret(auth_input.user_input.value());
          auto auth_block_state = std::make_unique<AuthBlockState>();
          auth_block_state->state = TpmBoundToPcrAuthBlockState();
          std::move(create_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::move(auth_block_state));
        });
    user_data_auth::AddAuthFactorRequest request;
    request.mutable_auth_factor()->set_type(
        user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
    request.mutable_auth_factor()->set_label(label);
    request.mutable_auth_factor()->mutable_password_metadata();
    request.mutable_auth_input()->mutable_password_input()->set_secret(
        password);
    request.set_auth_session_id(auth_session.serialized_token());

    TestFuture<CryptohomeStatus> add_future;
    auth_session.AddAuthFactor(request, add_future.GetCallback());

    if (add_future.Get().ok() ||
        !add_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }

    return add_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode AuthenticateRecoveryAuthFactor(
      const std::string& auth_factor_label,
      const std::string& secret,
      AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_,
                GetAuthBlockTypeFromState(
                    AuthBlockStateTypeIs<CryptohomeRecoveryAuthBlockState>()))
        .WillRepeatedly(Return(AuthBlockType::kCryptohomeRecovery));
    EXPECT_CALL(auth_block_utility_,
                DeriveKeyBlobsWithAuthBlock(AuthBlockType::kCryptohomeRecovery,
                                            _, _, _))
        .WillOnce([&secret](auto auth_block_type, auto auth_input,
                            auto auth_state, auto derive_callback) {
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key = brillo::SecureBlob(secret);
          std::move(derive_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::nullopt);
        });
    // Prepare recovery authentication request.
    std::string auth_factor_labels[] = {auth_factor_label};
    user_data_auth::AuthInput auth_input_proto;
    auth_input_proto.mutable_cryptohome_recovery_input()
        ->mutable_recovery_response();
    TestFuture<CryptohomeStatus> authenticate_future;
    // Authenticate using recovery.
    auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                        authenticate_future.GetCallback());
    // Verify.
    if (authenticate_future.Get().ok() ||
        !authenticate_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }
    return authenticate_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode AuthenticatePasswordAuthFactor(
      const std::string& password, AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_,
                GetAuthBlockTypeFromState(
                    AuthBlockStateTypeIs<TpmBoundToPcrAuthBlockState>()))
        .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
    EXPECT_CALL(
        auth_block_utility_,
        DeriveKeyBlobsWithAuthBlock(AuthBlockType::kTpmBoundToPcr, _, _, _))
        .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                     const AuthBlockState& auth_state,
                     AuthBlock::DeriveCallback derive_callback) {
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key =
              GetFakeDerivedSecret(auth_input.user_input.value());
          std::move(derive_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::nullopt);
        });

    TestFuture<CryptohomeStatus> authenticate_future;
    std::string auth_factor_labels[] = {kFakeLabel};
    user_data_auth::AuthInput auth_input_proto;
    auth_input_proto.mutable_password_input()->set_secret(password);
    auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                        authenticate_future.GetCallback());

    // Verify.
    if (authenticate_future.Get().ok() ||
        !authenticate_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }
    return authenticate_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode UpdatePasswordAuthFactor(
      const std::string& new_password, AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
        .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
    EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(
                                         AuthBlockType::kTpmBoundToPcr, _, _))
        .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                     AuthBlock::CreateCallback create_callback) {
          // Make an arbitrary auth block state type can be used in this test.
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key =
              GetFakeDerivedSecret(auth_input.user_input.value());
          auto auth_block_state = std::make_unique<AuthBlockState>();
          auth_block_state->state = TpmBoundToPcrAuthBlockState();
          std::move(create_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::move(auth_block_state));
        });

    user_data_auth::UpdateAuthFactorRequest request;
    request.set_auth_session_id(auth_session.serialized_token());
    request.set_auth_factor_label(kFakeLabel);
    request.mutable_auth_factor()->set_type(
        user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
    request.mutable_auth_factor()->set_label(kFakeLabel);
    request.mutable_auth_factor()->mutable_password_metadata();
    request.mutable_auth_input()->mutable_password_input()->set_secret(
        new_password);

    TestFuture<CryptohomeStatus> update_future;
    auth_session.UpdateAuthFactor(request, update_future.GetCallback());

    if (update_future.Get().ok() ||
        !update_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }

    return update_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode UpdateAuthFactorMetadata(
      user_data_auth::AuthFactor& auth_factor_proto,
      AuthSession& auth_session) {
    user_data_auth::UpdateAuthFactorMetadataRequest request;
    request.set_auth_session_id(auth_session.serialized_token());
    request.set_auth_factor_label(auth_factor_proto.label());
    *request.mutable_auth_factor() = std::move(auth_factor_proto);

    TestFuture<CryptohomeStatus> update_future;
    auth_session.UpdateAuthFactorMetadata(request, update_future.GetCallback());

    if (update_future.Get().ok() ||
        !update_future.Get().status()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }

    return update_future.Get().status()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode AddPinAuthFactor(
      const std::string& pin, AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
        .WillRepeatedly(ReturnValue(AuthBlockType::kPinWeaver));
    EXPECT_CALL(auth_block_utility_,
                CreateKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _))
        .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                     AuthBlock::CreateCallback create_callback) {
          // Make an arbitrary auth block state type can be used in this test.
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key =
              GetFakeDerivedSecret(auth_input.user_input.value());
          key_blobs->reset_secret = auth_input.reset_secret;
          auto auth_block_state = std::make_unique<AuthBlockState>();
          auth_block_state->state = PinWeaverAuthBlockState();
          std::move(create_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::move(auth_block_state));
        });
    // Calling AddAuthFactor.
    user_data_auth::AddAuthFactorRequest add_pin_request;
    add_pin_request.set_auth_session_id(auth_session.serialized_token());
    add_pin_request.mutable_auth_factor()->set_type(
        user_data_auth::AUTH_FACTOR_TYPE_PIN);
    add_pin_request.mutable_auth_factor()->set_label(kFakePinLabel);
    add_pin_request.mutable_auth_factor()->mutable_pin_metadata();
    add_pin_request.mutable_auth_input()->mutable_pin_input()->set_secret(pin);
    TestFuture<CryptohomeStatus> add_future;
    auth_session.AddAuthFactor(add_pin_request, add_future.GetCallback());

    if (add_future.Get().ok() ||
        !add_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }
    return add_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode AddFirstFingerprintAuthFactor(
      AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
        .WillOnce(ReturnValue(AuthBlockType::kFingerprint));
    EXPECT_CALL(auth_block_utility_,
                CreateKeyBlobsWithAuthBlock(AuthBlockType::kFingerprint, _, _))
        .WillOnce([&](AuthBlockType auth_block_type,
                      const AuthInput& auth_input,
                      AuthBlock::CreateCallback create_callback) {
          // During the first create, rate-limiter should be empty.
          EXPECT_FALSE(auth_input.rate_limiter_label.has_value());
          EXPECT_FALSE(auth_input.reset_secret.has_value());
          // Make an arbitrary auth block state type that can be used in the
          // tests.
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key = brillo::SecureBlob(kFakeVkkKey);
          key_blobs->rate_limiter_label = kFakeRateLimiterLabel;
          key_blobs->reset_secret = brillo::SecureBlob(kFakeResetSecret);
          auto auth_block_state = std::make_unique<AuthBlockState>();
          FingerprintAuthBlockState fingerprint_state =
              FingerprintAuthBlockState();
          fingerprint_state.template_id = kFakeRecordId;
          fingerprint_state.gsc_secret_label = kFakeFpLabel;
          auth_block_state->state = fingerprint_state;
          std::move(create_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::move(auth_block_state));
        });
    // Calling AddAuthFactor.
    user_data_auth::AddAuthFactorRequest request;
    request.set_auth_session_id(auth_session.serialized_token());
    request.mutable_auth_factor()->set_type(
        user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
    request.mutable_auth_factor()->set_label(kFakeFingerprintLabel);
    request.mutable_auth_factor()->mutable_fingerprint_metadata();
    request.mutable_auth_input()->mutable_fingerprint_input();

    TestFuture<CryptohomeStatus> add_future;
    auth_session.AddAuthFactor(request, add_future.GetCallback());

    if (add_future.Get().ok() ||
        !add_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }

    return add_future.Get()->local_legacy_error().value();
  }

  user_data_auth::CryptohomeErrorCode AddSubsequentFingerprintAuthFactor(
      AuthSession& auth_session) {
    EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
        .WillOnce(ReturnValue(AuthBlockType::kFingerprint));
    EXPECT_CALL(auth_block_utility_,
                CreateKeyBlobsWithAuthBlock(AuthBlockType::kFingerprint, _, _))
        .WillOnce([&](AuthBlockType auth_block_type,
                      const AuthInput& auth_input,
                      AuthBlock::CreateCallback create_callback) {
          // During the subsequent create, rate-limiter should already exist.
          ASSERT_TRUE(auth_input.rate_limiter_label.has_value());
          EXPECT_EQ(auth_input.rate_limiter_label.value(),
                    kFakeRateLimiterLabel);
          ASSERT_TRUE(auth_input.reset_secret.has_value());
          EXPECT_EQ(auth_input.reset_secret.value(),
                    brillo::SecureBlob(kFakeResetSecret));
          // Make an arbitrary auth block state type that can be used in the
          // tests.
          auto key_blobs = std::make_unique<KeyBlobs>();
          key_blobs->vkk_key = brillo::SecureBlob(kFakeSecondVkkKey);
          auto auth_block_state = std::make_unique<AuthBlockState>();
          FingerprintAuthBlockState fingerprint_state =
              FingerprintAuthBlockState();
          fingerprint_state.template_id = kFakeSecondRecordId;
          fingerprint_state.gsc_secret_label = kFakeSecondFpLabel;
          auth_block_state->state = fingerprint_state;
          std::move(create_callback)
              .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                   std::move(auth_block_state));
        });
    // Calling AddAuthFactor.
    user_data_auth::AddAuthFactorRequest add_request;
    add_request.set_auth_session_id(auth_session.serialized_token());
    add_request.mutable_auth_factor()->set_type(
        user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
    add_request.mutable_auth_factor()->set_label(kFakeSecondFingerprintLabel);
    add_request.mutable_auth_factor()->mutable_fingerprint_metadata();
    add_request.mutable_auth_input()->mutable_fingerprint_input();
    TestFuture<CryptohomeStatus> add_future;
    auth_session.AddAuthFactor(add_request, add_future.GetCallback());

    if (add_future.Get().ok() ||
        !add_future.Get()->local_legacy_error().has_value()) {
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }

    return add_future.Get()->local_legacy_error().value();
  }
};

// Test that the UserSecretStash is created on the user creation, in case the
// UserSecretStash experiment is on.
TEST_F(AuthSessionWithUssExperimentTest, UssCreation) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  EXPECT_FALSE(auth_session.has_user_secret_stash());
  EXPECT_TRUE(auth_session.OnUserCreated().ok());

  // Verify.
  EXPECT_TRUE(auth_session.has_user_secret_stash());
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
}

// Test that no UserSecretStash is created for an ephemeral user.
TEST_F(AuthSessionWithUssExperimentTest, NoUssForEphemeral) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = true,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());

  // Verify.
  EXPECT_FALSE(auth_session.has_user_secret_stash());
}

// Test that a new auth factor can be added to the newly created user, in case
// the UserSecretStash experiment is on.
TEST_F(AuthSessionWithUssExperimentTest, AddPasswordAuthFactorViaUss) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  // Test.
  // Setting the expectation that the auth block utility will create key blobs.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_,
              CreateKeyBlobsWithAuthBlock(AuthBlockType::kTpmBoundToPcr, _, _))
      .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                   AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state type can be used in this test.
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob("fake vkk key");
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = TpmBoundToPcrAuthBlockState();
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state));
      });
  // Calling AddAuthFactor.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify
  EXPECT_THAT(add_future.Get(), IsOk());
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));

  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword)));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeLabel), Optional(_));
}

// Test that a new auth factor can be added to the newly created user using
// asynchronous key creation.
TEST_F(AuthSessionWithUssExperimentTest, AddPasswordAuthFactorViaAsyncUss) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  // Test.
  // Setting the expectation that the auth block utility will create key blobs.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_,
              CreateKeyBlobsWithAuthBlock(AuthBlockType::kTpmBoundToPcr, _, _))
      .WillOnce([this](AuthBlockType, const AuthInput&,
                       AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state, but schedule it to run later to
        // simulate an proper async key creation.
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob("fake vkk key");
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = TpmBoundToPcrAuthBlockState();
        task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(std::move(create_callback),
                           OkStatus<CryptohomeCryptoError>(),
                           std::move(key_blobs), std::move(auth_block_state)));
      });
  // Calling AddAuthFactor.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  EXPECT_THAT(add_future.Get(), IsOk());
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));

  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword)));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeLabel), Optional(_));
}

// Test the new auth factor failure path when asynchronous key creation fails.
TEST_F(AuthSessionWithUssExperimentTest,
       AddPasswordAuthFactorViaAsyncUssFails) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  // Test.
  // Setting the expectation that the auth block utility will be called an that
  // key blob creation will fail.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_,
              CreateKeyBlobsWithAuthBlock(AuthBlockType::kTpmBoundToPcr, _, _))
      .WillOnce([this](AuthBlockType, const AuthInput&,
                       AuthBlock::CreateCallback create_callback) {
        // Have the creation callback report an error.
        task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(
                std::move(create_callback),
                MakeStatus<CryptohomeCryptoError>(
                    kErrorLocationForTestingAuthSession,
                    error::ErrorActionSet(
                        {error::PossibleAction::kDevCheckUnexpectedState}),
                    CryptoError::CE_OTHER_CRYPTO),
                nullptr, nullptr));
      });
  // Calling AddAuthFactor.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  ASSERT_THAT(add_future.Get(), NotOk());
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
  ASSERT_EQ(add_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED);
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors, IsEmpty());
}

// Test that a new auth factor cannot be added for an unauthenticated
// authsession.
TEST_F(AuthSessionWithUssExperimentTest, AddPasswordAuthFactorUnAuthenticated) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  // Test and Verify.
  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  ASSERT_THAT(add_future.Get(), NotOk());
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
  ASSERT_EQ(add_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_UNAUTHENTICATED_AUTH_SESSION);
}

// Test that a new auth factor and a pin can be added to the newly created user,
// in case the UserSecretStash experiment is on.
TEST_F(AuthSessionWithUssExperimentTest, AddPasswordAndPinAuthFactorViaUss) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());
  // Add a password first.
  // Setting the expectation that the auth block utility will create key blobs.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_,
              CreateKeyBlobsWithAuthBlock(AuthBlockType::kTpmBoundToPcr, _, _))
      .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                   AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state type can be used in this test.
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob("fake vkk key");
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = TpmBoundToPcrAuthBlockState();
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state));
      });
  // Calling AddAuthFactor.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  // Test and Verify.
  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  EXPECT_THAT(add_future.Get(), IsOk());

  // Setting the expectation that the auth block utility will create key blobs.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kPinWeaver));
  EXPECT_CALL(auth_block_utility_,
              CreateKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _))
      .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                   AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state type can be used in this test.
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob("fake vkk key");
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = PinWeaverAuthBlockState();
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state));
      });
  // Calling AddAuthFactor.
  user_data_auth::AddAuthFactorRequest add_pin_request;
  add_pin_request.set_auth_session_id(auth_session.serialized_token());
  add_pin_request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PIN);
  add_pin_request.mutable_auth_factor()->set_label(kFakePinLabel);
  add_pin_request.mutable_auth_factor()->mutable_pin_metadata();
  add_pin_request.mutable_auth_input()->mutable_pin_input()->set_secret(
      kFakePin);
  // Test and Verify.
  TestFuture<CryptohomeStatus> add_pin_future;
  auth_session.AddAuthFactor(add_pin_request, add_pin_future.GetCallback());

  // Verify.
  ASSERT_THAT(add_pin_future.Get(), IsOk());
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword),
                          Pair(kFakePinLabel, AuthFactorType::kPin)));
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test that an existing user with an existing password auth factor can be
// authenticated, in case the UserSecretStash experiment is on.
TEST_F(AuthSessionWithUssExperimentTest, AuthenticatePasswordAuthFactorViaUss) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, kFakeLabel,
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{.state = TpmBoundToPcrAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakeLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<TpmBoundToPcrAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(
                                       AuthBlockType::kTpmBoundToPcr, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::nullopt);
      });
  // Calling AuthenticateAuthFactor.
  TestFuture<CryptohomeStatus> authenticate_future;
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test that an existing user with an existing password auth factor can be
// authenticated, using asynchronous key derivation.
TEST_F(AuthSessionWithUssExperimentTest,
       AuthenticatePasswordAuthFactorViaAsyncUss) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, kFakeLabel,
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{.state = TpmBoundToPcrAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakeLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<TpmBoundToPcrAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(
                                       AuthBlockType::kTpmBoundToPcr, _, _, _))
      .WillOnce([this, &kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        task_runner_->PostTask(
            FROM_HERE, base::BindOnce(std::move(derive_callback),
                                      OkStatus<CryptohomeCryptoError>(),
                                      std::move(key_blobs), std::nullopt));
      });
  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test then failure path with an existing user with an existing password auth
// factor when the asynchronous derivation fails.
TEST_F(AuthSessionWithUssExperimentTest,
       AuthenticatePasswordAuthFactorViaAsyncUssFails) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, kFakeLabel,
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{.state = TpmBoundToPcrAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakeLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<TpmBoundToPcrAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, DeriveKeyBlobsWithAuthBlock(
                                       AuthBlockType::kTpmBoundToPcr, _, _, _))
      .WillOnce([this](AuthBlockType auth_block_type,
                       const AuthInput& auth_input,
                       const AuthBlockState& auth_state,
                       AuthBlock::DeriveCallback derive_callback) {
        task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(
                std::move(derive_callback),
                MakeStatus<CryptohomeCryptoError>(
                    kErrorLocationForTestingAuthSession,
                    error::ErrorActionSet(
                        {error::PossibleAction::kDevCheckUnexpectedState}),
                    CryptoError::CE_OTHER_CRYPTO),
                nullptr, std::nullopt));
      });

  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  ASSERT_THAT(authenticate_future.Get(), NotOk());
  EXPECT_EQ(authenticate_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
  EXPECT_FALSE(auth_session.has_user_secret_stash());
}

// Test that an existing user with an existing pin auth factor can be
// authenticated, in case the UserSecretStash experiment is on.
TEST_F(AuthSessionWithUssExperimentTest, AuthenticatePinAuthFactorViaUss) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, kFakePinLabel,
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakePinLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<PinWeaverAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kPinWeaver));
  EXPECT_CALL(auth_block_utility_,
              DeriveKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::nullopt);
      });
  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_pin_input()->set_secret(kFakePin);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());
}

// Test that an existing user with an existing pin auth factor can be
// authenticated and then re-created if the derive suggests it.
TEST_F(AuthSessionWithUssExperimentTest,
       AuthenticatePinAuthFactorViaUssWithRecreate) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, kFakePinLabel,
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakePinLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs,
  // and then that there will be additional calls to re-create them.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<PinWeaverAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kPinWeaver));
  EXPECT_CALL(auth_block_utility_,
              DeriveKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 AuthBlock::SuggestedAction::kRecreate);
      });
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kPinWeaver));
  EXPECT_CALL(auth_block_utility_,
              CreateKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _))
      .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                   AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state type can be used in this test.
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob("fake vkk key");
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = PinWeaverAuthBlockState();
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state));
      });
  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_pin_input()->set_secret(kFakePin);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());
}

// Test that an existing user with an existing pin auth factor can be
// authenticated and then re-created if the derive suggests it. This test
// verifies that the authenticate still works even if the re-create fails.
TEST_F(AuthSessionWithUssExperimentTest,
       AuthenticatePinAuthFactorViaUssWithRecreateThatFails) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, kFakePinLabel,
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakePinLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs,
  // and then that there will be additional calls to re-create them.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<PinWeaverAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kPinWeaver));
  EXPECT_CALL(auth_block_utility_,
              DeriveKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 AuthBlock::SuggestedAction::kRecreate);
      });
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly([](auto...) -> CryptoStatusOr<AuthBlockType> {
        return MakeStatus<CryptohomeCryptoError>(
            kErrorLocationForTestingAuthSession,
            error::ErrorActionSet(
                {error::PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO);
      });
  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_pin_input()->set_secret(kFakePin);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());
}

// Test that if a user gets locked out, the AuthFactorStatusUpdate timer is set
// and called periodically.
TEST_F(AuthSessionTest, AuthFactorStatusUpdateTimerTest) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor. An arbitrary auth block state is used in this
  // test.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, kFakePinLabel,
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{.le_label = 0xbaadf00d}});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakePinLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  auto mock_le_manager = std::make_unique<MockLECredentialManager>();
  MockLECredentialManager* mock_le_manager_ptr = mock_le_manager.get();
  crypto_.set_le_manager_for_testing(std::move(mock_le_manager));
  auth_session.SetAuthFactorStatusUpdateCallback(base::BindRepeating(
      [](user_data_auth::AuthFactorWithStatus, const std::string&) {}));
  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<PinWeaverAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kPinWeaver));
  EXPECT_CALL(auth_block_utility_,
              DeriveKeyBlobsWithAuthBlock(AuthBlockType::kPinWeaver, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(MakeStatus<error::CryptohomeCryptoError>(
                     kErrorLocationForTestingAuthSession,
                     error::ErrorActionSet(
                         {error::PrimaryAction::kIncorrectAuth}),
                     CryptoError::CE_CREDENTIAL_LOCKED),
                 nullptr, std::nullopt);
      });
  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  // The wrong pin needs to be sent multiple times. |wrong_pin| is set to be
  // different than |kFakePin|.
  std::string wrong_pin = "232323";
  auth_input_proto.mutable_pin_input()->set_secret(wrong_pin);
  EXPECT_CALL(*mock_le_manager_ptr, GetDelayInSeconds(_))
      .WillRepeatedly([](auto) { return UINT32_MAX; });
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());
  EXPECT_THAT(authenticate_future.Get(), NotOk());
  // As currently the user is locked out until they log in via password, the
  // delay policy does not matter, but once the passwordless policy is set, this
  // timing should change to reflect that.
  task_environment_.FastForwardBy(kAuthFactorStatusUpdateDelay);
}

TEST_F(AuthSessionWithUssExperimentTest, AddCryptohomeRecoveryAuthFactor) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());
  // Setting the expectation that the auth block utility will create key blobs.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kCryptohomeRecovery));
  EXPECT_CALL(
      auth_block_utility_,
      CreateKeyBlobsWithAuthBlock(AuthBlockType::kCryptohomeRecovery, _, _))
      .WillOnce([](AuthBlockType auth_block_type, const AuthInput& auth_input,
                   AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state type can be used in this test.
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob("fake vkk key");
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = CryptohomeRecoveryAuthBlockState();
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state));
      });
  // Calling AddAuthFactor.
  user_data_auth::AddAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_cryptohome_recovery_metadata();
  request.mutable_auth_input()
      ->mutable_cryptohome_recovery_input()
      ->set_mediator_pub_key("mediator pub key");
  // Test and Verify.
  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(request, add_future.GetCallback());

  // Verify.
  EXPECT_THAT(add_future.Get(), IsOk());
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(
      stored_factors,
      ElementsAre(Pair(kFakeLabel, AuthFactorType::kCryptohomeRecovery)));
  // There should be no verifier for the recovery factor.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
}

TEST_F(AuthSessionWithUssExperimentTest,
       AuthenticateCryptohomeRecoveryAuthFactor) {
  // Setup.
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kCryptohomeRecovery, kFakeLabel,
      AuthFactorMetadata{.metadata = auth_factor::CryptohomeRecoveryMetadata()},
      AuthBlockState{.state = CryptohomeRecoveryAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::move(auth_factor),
                      AuthFactorStorageType::kUserSecretStash);

  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakeLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());

  // Test.
  // Setting the expectation that the auth block utility will generate recovery
  // request.
  EXPECT_CALL(auth_block_utility_, GenerateRecoveryRequest(_, _, _, _, _, _, _))
      .WillOnce([](const ObfuscatedUsername& obfuscated_username,
                   const cryptorecovery::RequestMetadata& request_metadata,
                   const brillo::Blob& epoch_response,
                   const CryptohomeRecoveryAuthBlockState& state,
                   const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
                   brillo::SecureBlob* out_recovery_request,
                   brillo::SecureBlob* out_ephemeral_pub_key) {
        *out_ephemeral_pub_key = brillo::SecureBlob("test");
        return OkStatus<CryptohomeCryptoError>();
      });
  EXPECT_FALSE(auth_session.has_user_secret_stash());

  // Calling GetRecoveryRequest.
  user_data_auth::GetRecoveryRequestRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);
  TestFuture<user_data_auth::GetRecoveryRequestReply> reply_future;
  auth_session.GetRecoveryRequest(
      request,
      reply_future
          .GetCallback<const user_data_auth::GetRecoveryRequestReply&>());

  // Verify.
  EXPECT_EQ(reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<CryptohomeRecoveryAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kCryptohomeRecovery));
  EXPECT_CALL(
      auth_block_utility_,
      DeriveKeyBlobsWithAuthBlock(AuthBlockType::kCryptohomeRecovery, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        EXPECT_THAT(
            auth_input.cryptohome_recovery_auth_input->ephemeral_pub_key,
            Optional(brillo::SecureBlob("test")));
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::nullopt);
      });

  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_cryptohome_recovery_input()
      ->mutable_recovery_response();
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());
  // There should be no verifier created for the recovery factor.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(), IsEmpty());
}

// Test scenario where we add a Smart Card/Challenge Response credential,
// and go through the authentication flow twice. On the second authentication,
// AuthSession should use the lightweight verify check.
TEST_F(AuthSessionWithUssExperimentTest, AuthenticateSmartCardAuthFactor) {
  // Setup.
  brillo::Blob public_key_spki_der = brillo::BlobFromString("public_key");
  const ObfuscatedUsername obfuscated_username =
      SanitizeUserName(kFakeUsername);
  const brillo::SecureBlob kFakePerCredentialSecret("fake-vkk");
  // Setting the expectation that the user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Generating the USS.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
      UserSecretStash::CreateRandom(FileSystemKeyset::CreateRandom());
  ASSERT_TRUE(uss_status.ok());
  std::unique_ptr<UserSecretStash> uss = std::move(uss_status).value();
  std::optional<brillo::SecureBlob> uss_main_key =
      UserSecretStash::CreateRandomMainKey();
  ASSERT_TRUE(uss_main_key.has_value());
  // Creating the auth factor.
  auto auth_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kSmartCard, kFakeLabel,
      AuthFactorMetadata{
          .metadata = auth_factor::SmartCardMetadata{.public_key_spki_der =
                                                         public_key_spki_der}},
      AuthBlockState{.state = ChallengeCredentialAuthBlockState()});
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(obfuscated_username, *auth_factor)
          .ok());
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(std::make_unique<AuthFactor>(*auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  // Adding the auth factor into the USS and persisting the latter.
  const KeyBlobs key_blobs = {.vkk_key = kFakePerCredentialSecret};
  std::optional<brillo::SecureBlob> wrapping_key =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(wrapping_key.has_value());
  EXPECT_TRUE(uss->AddWrappedMainKey(uss_main_key.value(), kFakeLabel,
                                     wrapping_key.value(),
                                     OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      uss->GetEncryptedContainer(uss_main_key.value());
  ASSERT_TRUE(encrypted_uss.ok());
  EXPECT_TRUE(user_secret_stash_storage_
                  .Persist(encrypted_uss.value(), obfuscated_username)
                  .ok());
  // Creating the auth session.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_TRUE(auth_session.user_exists());
  EXPECT_FALSE(auth_session.has_user_secret_stash());

  // Verify.
  EXPECT_EQ(auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(auth_session.authorized_intents(), IsEmpty());

  // Test.
  // Setting the expectation that the auth block utility will derive key blobs.
  EXPECT_CALL(auth_block_utility_,
              GetAuthBlockTypeFromState(
                  AuthBlockStateTypeIs<ChallengeCredentialAuthBlockState>()))
      .WillRepeatedly(Return(AuthBlockType::kChallengeCredential));
  EXPECT_CALL(
      auth_block_utility_,
      DeriveKeyBlobsWithAuthBlock(AuthBlockType::kChallengeCredential, _, _, _))
      .WillOnce([&kFakePerCredentialSecret](
                    AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = kFakePerCredentialSecret;
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::nullopt);
      });

  // Calling AuthenticateAuthFactor.
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_smart_card_input()->add_signature_algorithms(
      user_data_auth::CHALLENGE_RSASSA_PKCS1_V1_5_SHA256);
  auth_input_proto.mutable_smart_card_input()
      ->set_key_delegate_dbus_service_name("test_cc_dbus");
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_EQ(auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  // There should be a verifier created for the smart card factor.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(IsVerifierPtrWithLabel(kFakeLabel)));

  AuthFactorMap verify_auth_factor_map;
  auth_factor_map.Add(std::make_unique<AuthFactor>(*auth_factor),
                      AuthFactorStorageType::kUserSecretStash);
  AuthSession verify_auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(verify_auth_factor_map),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Simulate a successful key verification.
  EXPECT_CALL(challenge_credentials_helper_, VerifyKey(_, _, _, _))
      .WillOnce(ReplyToVerifyKey{/*is_key_valid=*/true});

  // Call AuthenticateAuthFactor again.
  TestFuture<CryptohomeStatus> verify_authenticate_future;
  verify_auth_session.AuthenticateAuthFactor(
      auth_factor_labels, auth_input_proto,
      verify_authenticate_future.GetCallback());
  EXPECT_THAT(verify_auth_session.authorized_intents(),
              UnorderedElementsAre(AuthIntent::kVerifyOnly));
}

// Test that AuthenticateAuthFactor succeeds for the `AuthIntent::kVerifyOnly`
// scenario, using a credential verifier.
TEST_F(AuthSessionWithUssExperimentTest, LightweightPasswordAuthentication) {
  // Setup.
  // Add the user session along with a verifier that's configured to pass.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, VerifyUser(SanitizeUserName(kFakeUsername)))
      .WillOnce(Return(true));
  auto verifier = std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, kFakeLabel,
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()});
  EXPECT_CALL(*verifier, VerifySync(_)).WillOnce(ReturnOk<CryptohomeError>());
  user_session->AddCredentialVerifier(std::move(verifier));
  EXPECT_TRUE(user_session_map_.Add(kFakeUsername, std::move(user_session)));
  // Create an AuthSession with a fake factor. No authentication mocks are set
  // up, because the lightweight authentication should be used in the test.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder().AddPassword<void>(kFakeLabel).Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  std::string auth_factor_labels[] = {kFakeLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakePass);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_THAT(auth_session.authorized_intents(),
              UnorderedElementsAre(AuthIntent::kVerifyOnly));
}

// Test that AuthenticateAuthFactor succeeds for the `AuthIntent::kVerifyOnly`
// scenario, using the legacy fingerprint.
TEST_F(AuthSessionWithUssExperimentTest, LightweightFingerprintAuthentication) {
  // Setup.
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, VerifyUser(SanitizeUserName(kFakeUsername)))
      .WillOnce(Return(true));
  auto verifier = std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kLegacyFingerprint, "", AuthFactorMetadata{});
  EXPECT_CALL(*verifier, VerifySync(_)).WillOnce(ReturnOk<CryptohomeError>());
  user_session->AddCredentialVerifier(std::move(verifier));
  EXPECT_TRUE(user_session_map_.Add(kFakeUsername, std::move(user_session)));
  // Create an AuthSession with no factors. No authentication mocks are set
  // up, because the lightweight authentication should be used in the test.
  AuthSession auth_session(
      AuthSession::Params{
          .username = kFakeUsername,
          .is_ephemeral_user = false,
          .intent = AuthIntent::kVerifyOnly,
          .timeout_timer = std::make_unique<base::WallClockTimer>(),
          .auth_factor_status_update_timer =
              std::make_unique<base::WallClockTimer>(),
          .user_exists = true,
          .auth_factor_map = AuthFactorMap(),
          .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_legacy_fingerprint_input();
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor({}, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_THAT(auth_session.authorized_intents(),
              UnorderedElementsAre(AuthIntent::kVerifyOnly));
}

// Test that PrepareAuthFactor succeeds for fingerprint with the purpose of
// authentication.
TEST_F(AuthSessionWithUssExperimentTest, PrepareLegacyFingerprintAuth) {
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  auto auth_session = std::make_unique<AuthSession>(
      AuthSession::Params{
          .username = kFakeUsername,
          .is_ephemeral_user = false,
          .intent = AuthIntent::kVerifyOnly,
          .timeout_timer = std::make_unique<base::WallClockTimer>(),
          .auth_factor_status_update_timer =
              std::make_unique<base::WallClockTimer>(),
          .user_exists = true,
          .auth_factor_map = AuthFactorMap(),
          .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_CALL(*bio_processor_,
              StartAuthenticateSession(auth_session->obfuscated_username(), _))
      .WillOnce([](auto&&, auto&& callback) { std::move(callback).Run(true); });

  // Test.
  TestFuture<CryptohomeStatus> prepare_future;
  user_data_auth::PrepareAuthFactorRequest request;
  request.set_auth_session_id(auth_session->serialized_token());
  request.set_auth_factor_type(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  request.set_purpose(user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);
  auth_session->PrepareAuthFactor(request, prepare_future.GetCallback());
  auth_session.reset();

  // Verify.
  ASSERT_THAT(prepare_future.Get(), IsOk());
}

// Test that PrepareAuthFactor succeeded for password.
TEST_F(AuthSessionWithUssExperimentTest, PreparePasswordFailure) {
  // Setup.
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  user_data_auth::PrepareAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.set_purpose(user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);
  TestFuture<CryptohomeStatus> prepare_future;
  auth_session.PrepareAuthFactor(request, prepare_future.GetCallback());

  // Verify.
  ASSERT_EQ(prepare_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(AuthSessionWithUssExperimentTest, TerminateAuthFactorBadTypeFailure) {
  // Setup.
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  user_data_auth::TerminateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  TestFuture<CryptohomeStatus> terminate_future;
  auth_session.TerminateAuthFactor(request, terminate_future.GetCallback());

  // Verify.
  ASSERT_EQ(terminate_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(AuthSessionWithUssExperimentTest,
       TerminateAuthFactorInactiveFactorFailure) {
  // Setup.
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  user_data_auth::TerminateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_type(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  TestFuture<CryptohomeStatus> terminate_future;
  auth_session.TerminateAuthFactor(request, terminate_future.GetCallback());

  // Verify.
  ASSERT_EQ(terminate_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(AuthSessionWithUssExperimentTest,
       TerminateAuthFactorLegacyFingerprintSuccess) {
  // Setup.
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_CALL(*bio_processor_,
              StartAuthenticateSession(auth_session.obfuscated_username(), _))
      .WillOnce([](auto&&, auto&& callback) { std::move(callback).Run(true); });
  TestFuture<CryptohomeStatus> prepare_future;
  user_data_auth::PrepareAuthFactorRequest prepare_request;
  prepare_request.set_auth_session_id(auth_session.serialized_token());
  prepare_request.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  prepare_request.set_purpose(user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);
  auth_session.PrepareAuthFactor(prepare_request, prepare_future.GetCallback());
  ASSERT_THAT(prepare_future.Get(), IsOk());

  // Test.
  user_data_auth::TerminateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_type(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  TestFuture<CryptohomeStatus> terminate_future;
  auth_session.TerminateAuthFactor(request, terminate_future.GetCallback());

  // Verify.
  ASSERT_THAT(terminate_future.Get(), IsOk());
}

TEST_F(AuthSessionWithUssExperimentTest, RemoveAuthFactor) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  error = AddPinAuthFactor(kFakePin, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Both password and pin are available.
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword),
                          Pair(kFakePinLabel, AuthFactorType::kPin)));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeLabel), Optional(_));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakePinLabel), Optional(_));

  // Test.

  // Calling RemoveAuthFactor for pin.
  user_data_auth::RemoveAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakePinLabel);

  TestFuture<CryptohomeStatus> remove_future;
  auth_session.RemoveAuthFactor(request, remove_future.GetCallback());

  EXPECT_THAT(remove_future.Get(), IsOk());

  // Only password is available.
  std::map<std::string, AuthFactorType> stored_factors_1 =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors_1,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword)));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeLabel), Optional(_));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakePinLabel),
              Eq(std::nullopt));

  // Calling AuthenticateAuthFactor for password succeeds.
  error = AuthenticatePasswordAuthFactor(kFakePass, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Calling AuthenticateAuthFactor for pin fails.
  std::string auth_factor_labels[] = {kFakePinLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_pin_input()->set_secret(kFakePin);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  ASSERT_THAT(authenticate_future.Get(), NotOk());
  EXPECT_EQ(authenticate_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  // The verifier still uses the password.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

TEST_F(AuthSessionWithUssExperimentTest,
       RemoveAuthFactorRemovesCredentialVerifier) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  error = AddPasswordAuthFactor(kFakeOtherLabel, kFakeOtherPass,
                                /*first_factor=*/false, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Both passwords are available, the first one should supply a verifier.
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword),
                          Pair(kFakeOtherLabel, AuthFactorType::kPassword)));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeLabel), Optional(_));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeOtherLabel),
              Optional(_));
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(
      user_session->GetCredentialVerifiers(),
      UnorderedElementsAre(
          IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass),
          IsVerifierPtrWithLabelAndPassword(kFakeOtherLabel, kFakeOtherPass)));

  // Test.

  // Calling RemoveAuthFactor for the second password.
  user_data_auth::RemoveAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeOtherLabel);

  TestFuture<CryptohomeStatus> remove_future;
  auth_session.RemoveAuthFactor(request, remove_future.GetCallback());

  EXPECT_THAT(remove_future.Get(), IsOk());

  // Only the first password is available.
  std::map<std::string, AuthFactorType> stored_factors_1 =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors_1,
              ElementsAre(Pair(kFakeLabel, AuthFactorType::kPassword)));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeLabel), Optional(_));
  EXPECT_THAT(auth_session.auth_factor_map().Find(kFakeOtherLabel),
              Eq(std::nullopt));

  // Calling AuthenticateAuthFactor for the first password succeeds.
  error = AuthenticatePasswordAuthFactor(kFakePass, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Calling AuthenticateAuthFactor for the second password fails.
  std::string auth_factor_labels[] = {kFakeOtherLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_password_input()->set_secret(kFakeOtherPass);
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  ASSERT_THAT(authenticate_future.Get(), NotOk());
  EXPECT_EQ(authenticate_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  // Now only the first password verifier is available.
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// The test adds, removes and adds the same auth factor again.
TEST_F(AuthSessionWithUssExperimentTest, RemoveAndReAddAuthFactor) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  error = AddPinAuthFactor(kFakePin, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  // Calling RemoveAuthFactor for pin.
  user_data_auth::RemoveAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakePinLabel);

  TestFuture<CryptohomeStatus> remove_future;
  auth_session.RemoveAuthFactor(request, remove_future.GetCallback());

  EXPECT_THAT(remove_future.Get(), IsOk());

  // Add the same pin auth factor again.
  error = AddPinAuthFactor(kFakePin, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // The verifier still uses the original password.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

TEST_F(AuthSessionWithUssExperimentTest, RemoveAuthFactorFailsForLastFactor) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.

  // Calling RemoveAuthFactor for password.
  user_data_auth::RemoveAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);

  TestFuture<CryptohomeStatus> remove_future;
  auth_session.RemoveAuthFactor(request, remove_future.GetCallback());

  // Verify.
  ASSERT_THAT(remove_future.Get(), NotOk());
  EXPECT_EQ(remove_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_REMOVE_CREDENTIALS_FAILED);
  // The verifier is still set after the removal failed.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

TEST_F(AuthSessionTest, RemoveAuthFactorFailsForUnauthenticatedAuthSession) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  user_data_auth::RemoveAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);
  TestFuture<CryptohomeStatus> remove_future;
  auth_session.RemoveAuthFactor(request, remove_future.GetCallback());

  ASSERT_THAT(remove_future.Get(), NotOk());
  EXPECT_EQ(remove_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_UNAUTHENTICATED_AUTH_SESSION);
}

TEST_F(AuthSessionWithUssExperimentTest, UpdateAuthFactor) {
  // Setup.
  std::string new_pass = "update fake pass";

  {
    AuthSession auth_session(
        {.username = kFakeUsername,
         .is_ephemeral_user = false,
         .intent = AuthIntent::kDecrypt,
         .timeout_timer = std::make_unique<base::WallClockTimer>(),
         .auth_factor_status_update_timer =
             std::make_unique<base::WallClockTimer>(),
         .user_exists = false,
         .auth_factor_map = AuthFactorMap(),
         .migrate_to_user_secret_stash = false},
        backing_apis_);

    // Creating the user.
    EXPECT_TRUE(auth_session.OnUserCreated().ok());
    EXPECT_TRUE(auth_session.has_user_secret_stash());

    user_data_auth::CryptohomeErrorCode error =
        user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

    // Calling AddAuthFactor.
    error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                  auth_session);
    EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

    // Test.

    // Calling UpdateAuthFactor.
    error = UpdatePasswordAuthFactor(new_pass, auth_session);
    EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

    // Force the creation of the user session, otherwise any verifiers added
    // will be destroyed when the session is.
    FindOrCreateUserSession(kFakeUsername);
  }

  AuthSession new_auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .WithUss()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_EQ(new_auth_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(new_auth_session.authorized_intents(), IsEmpty());

  // Verify.
  // The credential verifier uses the new password.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, new_pass)));
  // AuthenticateAuthFactor should succeed using the new password.
  user_data_auth::CryptohomeErrorCode error =
      AuthenticatePasswordAuthFactor(new_pass, new_auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(new_auth_session.status(), AuthStatus::kAuthStatusAuthenticated);
  EXPECT_THAT(
      new_auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
}

// Test that AddauthFactor successfully adds a PIN factor on a
// session that was authenticated via a recovery factor.
TEST_F(AuthSessionWithUssExperimentTest, AddPinAfterRecoveryAuth) {
  // Setup.
  {
    // Obtain AuthSession for user setup.
    AuthSession auth_session(
        {.username = kFakeUsername,
         .is_ephemeral_user = false,
         .intent = AuthIntent::kDecrypt,
         .timeout_timer = std::make_unique<base::WallClockTimer>(),
         .auth_factor_status_update_timer =
             std::make_unique<base::WallClockTimer>(),
         .user_exists = false,
         .auth_factor_map = AuthFactorMap(),
         .migrate_to_user_secret_stash = false},
        backing_apis_);
    // Create the user with password and recovery factors.
    EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
    EXPECT_EQ(AddPasswordAuthFactor(kFakeLabel, kFakePass,
                                    /*first_factor=*/true, auth_session),
              user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
    EXPECT_EQ(AddRecoveryAuthFactor(kRecoveryLabel, kFakeRecoverySecret,
                                    auth_session),
              user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  }

  // Obtain AuthSession for authentication.
  AuthSession new_auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .WithUss()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .AddRecovery(kRecoveryLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Authenticate the new auth session with recovery factor.
  EXPECT_EQ(AuthenticateRecoveryAuthFactor(kRecoveryLabel, kFakeRecoverySecret,
                                           new_auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(
      new_auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(new_auth_session.has_user_secret_stash());

  // Test adding a PIN AuthFactor.
  user_data_auth::CryptohomeErrorCode error =
      AddPinAuthFactor(kFakePin, new_auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Verify PIN factor is added.
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(stored_factors,
              UnorderedElementsAre(
                  Pair(kFakeLabel, AuthFactorType::kPassword),
                  Pair(kRecoveryLabel, AuthFactorType::kCryptohomeRecovery),
                  Pair(kFakePinLabel, AuthFactorType::kPin)));
  // Verify that reset secret for the pin label is added to USS.
  EXPECT_TRUE(new_auth_session.HasResetSecretInUssForTesting(kFakePinLabel));
}

// Test that UpdateAuthFactor successfully updates a password factor on a
// session that was authenticated via a recovery factor.
TEST_F(AuthSessionWithUssExperimentTest, UpdatePasswordAfterRecoveryAuth) {
  // Setup.
  constexpr char kNewFakePass[] = "new fake pass";
  {
    // Obtain AuthSession for user setup.
    AuthSession auth_session(
        {.username = kFakeUsername,
         .is_ephemeral_user = false,
         .intent = AuthIntent::kDecrypt,
         .timeout_timer = std::make_unique<base::WallClockTimer>(),
         .auth_factor_status_update_timer =
             std::make_unique<base::WallClockTimer>(),
         .user_exists = false,
         .auth_factor_map = AuthFactorMap(),
         .migrate_to_user_secret_stash = false},
        backing_apis_);
    // Create the user.
    EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
    // Add password AuthFactor.
    EXPECT_EQ(AddPasswordAuthFactor(kFakeLabel, kFakePass,
                                    /*first_factor=*/true, auth_session),
              user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

    // Add recovery AuthFactor.
    EXPECT_EQ(AddRecoveryAuthFactor(kRecoveryLabel, kFakeRecoverySecret,
                                    auth_session),
              user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  }

  // Set up mocks for the now-existing user.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Obtain AuthSession for authentication.
  AuthSession new_auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map =
           AfMapBuilder()
               .WithUss()
               .AddPassword<TpmBoundToPcrAuthBlockState>(kFakeLabel)
               .AddRecovery(kRecoveryLabel)
               .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Authenticate the new auth session with recovery factor.
  EXPECT_EQ(AuthenticateRecoveryAuthFactor(kRecoveryLabel, kFakeRecoverySecret,
                                           new_auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(
      new_auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));
  EXPECT_TRUE(new_auth_session.has_user_secret_stash());
  EXPECT_THAT(
      new_auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kDecrypt, AuthIntent::kVerifyOnly));

  // Test updating existing password factor.
  user_data_auth::CryptohomeErrorCode error =
      UpdatePasswordAuthFactor(kNewFakePass, new_auth_session);

  // Verify update succeeded.
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
}

TEST_F(AuthSessionWithUssExperimentTest, UpdateAuthFactorFailsForWrongLabel) {
  // Setup.
  AuthSession auth_session(
      AuthSession::Params{
          .username = kFakeUsername,
          .is_ephemeral_user = false,
          .intent = AuthIntent::kVerifyOnly,
          .timeout_timer = std::make_unique<base::WallClockTimer>(),
          .auth_factor_status_update_timer =
              std::make_unique<base::WallClockTimer>(),
          .user_exists = false,
          .auth_factor_map = AuthFactorMap(),
          .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  std::string new_pass = "update fake pass";

  // Test.

  // Calling UpdateAuthFactor.
  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label("different new label");
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(new_pass);

  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(request, update_future.GetCallback());

  // Verify.
  ASSERT_THAT(update_future.Get(), NotOk());
  EXPECT_EQ(update_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  // The verifier still uses the original password.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

TEST_F(AuthSessionWithUssExperimentTest, UpdateAuthFactorFailsForWrongType) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.

  // Calling UpdateAuthFactor.
  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label(kFakeLabel);
  request.mutable_auth_factor()->set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_pin_metadata();
  request.mutable_auth_input()->mutable_pin_input()->set_secret(kFakePin);

  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(request, update_future.GetCallback());

  // Verify.
  ASSERT_THAT(update_future.Get(), NotOk());
  EXPECT_EQ(update_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  // The verifier still uses the original password.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

TEST_F(AuthSessionWithUssExperimentTest,
       UpdateAuthFactorFailsWhenLabelDoesntExist) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.

  // Calling UpdateAuthFactor.
  user_data_auth::UpdateAuthFactorRequest request;
  request.set_auth_session_id(auth_session.serialized_token());
  request.set_auth_factor_label("label doesn't exist");
  request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  request.mutable_auth_factor()->set_label(kFakeLabel);
  request.mutable_auth_factor()->mutable_password_metadata();
  request.mutable_auth_input()->mutable_password_input()->set_secret(kFakePass);

  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(request, update_future.GetCallback());

  // Verify.
  ASSERT_THAT(update_future.Get(), NotOk());
  EXPECT_EQ(update_future.Get()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND);
  // The verifier still uses the original password.
  UserSession* user_session = FindOrCreateUserSession(kFakeUsername);
  EXPECT_THAT(user_session->GetCredentialVerifiers(),
              UnorderedElementsAre(
                  IsVerifierPtrWithLabelAndPassword(kFakeLabel, kFakePass)));
}

// Test that `UpdateAuthFactor` fails when the auth block derivation fails (but
// doesn't crash).
TEST_F(AuthSessionTest, UpdateAuthFactorFailsInAuthBlock) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  // Creating the user.
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  // Adding the password VK.
  EXPECT_CALL(auth_block_utility_, SelectAuthBlockTypeForCreation(_))
      .WillRepeatedly(ReturnValue(AuthBlockType::kTpmBoundToPcr));
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillOnce([](auto, auto, AuthBlock::CreateCallback create_callback) {
        // Make an arbitrary auth block state type can be used in this test.
        auto key_blobs = std::make_unique<KeyBlobs>();
        auto auth_block_state = std::make_unique<AuthBlockState>();
        auth_block_state->state = TpmBoundToPcrAuthBlockState();
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::move(auth_block_state));
      })
      .RetiresOnSaturation();
  EXPECT_CALL(keyset_management_, AddInitialKeyset(_, _, _, _, _, _, _))
      .WillOnce(
          [](auto, auto, const KeyData& key_data, auto, auto, auto, auto) {
            auto vk = std::make_unique<VaultKeyset>();
            vk->SetKeyData(key_data);
            return vk;
          });
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kFakeLabel))
      .WillOnce(
          [](auto, auto) { return CreatePasswordVaultKeyset(kFakeLabel); });
  user_data_auth::AddAuthFactorRequest add_request;
  add_request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  add_request.mutable_auth_factor()->set_label(kFakeLabel);
  add_request.mutable_auth_factor()->mutable_password_metadata();
  add_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kFakePass);
  add_request.set_auth_session_id(auth_session.serialized_token());
  TestFuture<CryptohomeStatus> add_future;
  auth_session.AddAuthFactor(add_request, add_future.GetCallback());
  EXPECT_THAT(add_future.Get(), IsOk());
  // Setting the expectations for the new auth block creation. The mock is set
  // to fail.
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillOnce([](auto, auto, AuthBlock::CreateCallback create_callback) {
        std::move(create_callback)
            .Run(MakeStatus<CryptohomeCryptoError>(
                     kErrorLocationForTestingAuthSession,
                     error::ErrorActionSet(
                         {error::PossibleAction::kDevCheckUnexpectedState}),
                     CryptoError::CE_OTHER_CRYPTO),
                 nullptr, nullptr);
      });

  // Test.
  // Preparing UpdateAuthFactor parameters.
  user_data_auth::UpdateAuthFactorRequest update_request;
  update_request.set_auth_session_id(auth_session.serialized_token());
  update_request.set_auth_factor_label(kFakeLabel);
  update_request.mutable_auth_factor()->set_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  update_request.mutable_auth_factor()->set_label(kFakeLabel);
  update_request.mutable_auth_factor()->mutable_password_metadata();
  update_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kFakePass);
  // Calling UpdateAuthFactor.
  TestFuture<CryptohomeStatus> update_future;
  auth_session.UpdateAuthFactor(update_request, update_future.GetCallback());

  // Verify.
  EXPECT_THAT(update_future.Get(), NotOk());
}

TEST_F(AuthSessionWithUssExperimentTest, UpdateAuthFactorMetadataSuccess) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  user_data_auth::AuthFactor new_auth_factor;
  std::string kFakeChromeVersion = "fake chrome version";
  std::string kUserSpecifiedName = "password";

  new_auth_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  new_auth_factor.set_label(kFakeLabel);
  new_auth_factor.mutable_password_metadata();
  new_auth_factor.mutable_common_metadata()->set_chrome_version_last_updated(
      kFakeChromeVersion);
  new_auth_factor.mutable_common_metadata()->set_user_specified_name(
      kUserSpecifiedName);

  error = UpdateAuthFactorMetadata(new_auth_factor, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  auto loaded_auth_factor = auth_factor_manager_.LoadAuthFactor(
      SanitizeUserName(kFakeUsername), AuthFactorType::kPassword, kFakeLabel);
  EXPECT_THAT(loaded_auth_factor, IsOk());
  EXPECT_EQ(loaded_auth_factor.value()->type(), AuthFactorType::kPassword);
  EXPECT_EQ(loaded_auth_factor.value()->label(), kFakeLabel);
  EXPECT_EQ(
      loaded_auth_factor.value()->metadata().common.chrome_version_last_updated,
      kFakeChromeVersion);
  EXPECT_EQ(loaded_auth_factor.value()->metadata().common.user_specified_name,
            kUserSpecifiedName);

  // Calling AuthenticateAuthFactor with the password succeeds.
  error = AuthenticatePasswordAuthFactor(kFakePass, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
}

TEST_F(AuthSessionWithUssExperimentTest,
       UpdateAuthFactorMetadataEmptyLabelFailure) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  user_data_auth::AuthFactor new_auth_factor;

  new_auth_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  new_auth_factor.set_label("");
  new_auth_factor.mutable_password_metadata();

  error = UpdateAuthFactorMetadata(new_auth_factor, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(AuthSessionWithUssExperimentTest,
       UpdateAuthFactorMetadataWrongLabelFailure) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  user_data_auth::AuthFactor new_auth_factor;

  new_auth_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  new_auth_factor.set_label(kFakeOtherLabel);
  new_auth_factor.mutable_password_metadata();

  error = UpdateAuthFactorMetadata(new_auth_factor, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(AuthSessionWithUssExperimentTest,
       UpdateAuthFactorMetadataLongNameFailure) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  user_data_auth::AuthFactor new_auth_factor;
  std::string extra_long_name(kUserSpecifiedNameSizeLimit + 1, 'x');

  new_auth_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  new_auth_factor.set_label(kFakeLabel);
  new_auth_factor.mutable_password_metadata();
  new_auth_factor.mutable_common_metadata()->set_user_specified_name(
      extra_long_name);

  error = UpdateAuthFactorMetadata(new_auth_factor, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(AuthSessionWithUssExperimentTest,
       UpdateAuthFactorMetadataWrongTypeFailure) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_THAT(auth_session.OnUserCreated(), IsOk());
  EXPECT_TRUE(auth_session.has_user_secret_stash());

  user_data_auth::CryptohomeErrorCode error =
      user_data_auth::CRYPTOHOME_ERROR_NOT_SET;

  // Calling AddAuthFactor.
  error = AddPasswordAuthFactor(kFakeLabel, kFakePass, /*first_factor=*/true,
                                auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  user_data_auth::AuthFactor new_auth_factor;

  new_auth_factor.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  new_auth_factor.set_label(kFakeLabel);
  new_auth_factor.mutable_pin_metadata();

  error = UpdateAuthFactorMetadata(new_auth_factor, auth_session);
  EXPECT_EQ(error, user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

// Test that AuthenticateAuthFactor succeeds for the `AuthIntent::kWebAuthn`
// scenario, using the legacy fingerprint.
TEST_F(AuthSessionWithUssExperimentTest, FingerprintAuthenticationForWebAuthn) {
  // Setup.
  // Add the user session. Configure the credential verifier mock to succeed.
  auto user_session = std::make_unique<MockUserSession>();
  EXPECT_CALL(*user_session, VerifyUser(SanitizeUserName(kFakeUsername)))
      .WillOnce(Return(true));
  auto verifier = std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kLegacyFingerprint, "", AuthFactorMetadata{});
  EXPECT_CALL(*verifier, VerifySync(_)).WillOnce(ReturnOk<CryptohomeError>());
  user_session->AddCredentialVerifier(std::move(verifier));
  EXPECT_TRUE(user_session_map_.Add(kFakeUsername, std::move(user_session)));
  // Create an AuthSession and add a mock for a successful auth block verify.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kWebAuthn,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Test.
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_legacy_fingerprint_input();
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor({}, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  EXPECT_THAT(
      auth_session.authorized_intents(),
      UnorderedElementsAre(AuthIntent::kVerifyOnly, AuthIntent::kWebAuthn));
}

// Test that we can authenticate a old-style kiosk VK, and migrate it to USS
// correctly. These old VKs show up as password VKs and so we need the
// authenticate to successfully convert it to a kiosk based on the input.
TEST_F(AuthSessionWithUssExperimentTest, AuthenticatePasswordVkToKioskUss) {
  // Setup.
  // Create a factor containing a password that will become a kiosk factor.
  AuthFactorMap auth_factor_map;
  auth_factor_map.Add(
      std::make_unique<AuthFactor>(
          AuthFactorType::kPassword, kLegacyLabel,
          AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
          AuthBlockState()),
      AuthFactorStorageType::kVaultKeyset);
  // Start a session with this single factor and USS migration enabled.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = std::move(auth_factor_map),
       .migrate_to_user_secret_stash = true},
      backing_apis_);
  // Helpers to make keysets and keyblobs in the test.
  auto make_vk = [this]() {
    auto vk = std::make_unique<VaultKeyset>();
    vk->Initialize(backing_apis_.platform, backing_apis_.crypto);
    vk->SetLegacyIndex(0);
    vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED);
    TpmNotBoundToPcrAuthBlockState state;
    state.tpm_key = brillo::SecureBlob(32, 'T');
    vk->SetTpmNotBoundToPcrState(state);
    return vk;
  };
  auto make_key_blobs = []() {
    auto key_blobs = std::make_unique<KeyBlobs>();
    key_blobs->vkk_key = brillo::SecureBlob(32, 'J');
    return key_blobs;
  };
  // Called within the converter_.PopulateKeyDataForVK(). We return an empty VK
  // with no KeyData, like a legacy kiosk VK would have. We also have to fake
  // out the actual authentication calls. Since the point here is to test the
  // migration, not the authentication itself, we just respond with "yes, all
  // good" everywhere.
  EXPECT_CALL(keyset_management_, GetVaultKeyset(_, kLegacyLabel))
      .WillRepeatedly([&](auto...) { return make_vk(); });
  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kScrypt));
  EXPECT_CALL(auth_block_utility_,
              DeriveKeyBlobsWithAuthBlock(AuthBlockType::kScrypt, _, _, _))
      .WillOnce([&](AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), make_key_blobs(),
                 std::nullopt);
      });
  EXPECT_CALL(keyset_management_, GetValidKeyset(_, _, _))
      .WillOnce([&](auto...) { return make_vk(); });
  EXPECT_CALL(keyset_management_, RemoveKeysetFile(_))
      .WillOnce(Return(OkStatus<CryptohomeError>()));
  // These calls will happen during the migration.
  EXPECT_CALL(auth_block_utility_, CreateKeyBlobsWithAuthBlock(_, _, _))
      .WillOnce([&](AuthBlockType auth_block_type, const AuthInput& auth_input,
                    AuthBlock::CreateCallback create_callback) {
        std::move(create_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), make_key_blobs(),
                 std::make_unique<AuthBlockState>());
      });

  // Test.
  std::string auth_factor_labels[] = {kLegacyLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_kiosk_input();
  TestFuture<CryptohomeStatus> authenticate_future;
  auth_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                      authenticate_future.GetCallback());

  // Verify.
  EXPECT_THAT(authenticate_future.Get(), IsOk());
  ASSERT_THAT(auth_session.auth_factor_map().size(), Eq(1));
  AuthFactorMap::ValueView stored_auth_factor =
      *auth_session.auth_factor_map().begin();
  const AuthFactor& auth_factor = stored_auth_factor.auth_factor();
  EXPECT_THAT(stored_auth_factor.storage_type(),
              Eq(AuthFactorStorageType::kUserSecretStash));
  EXPECT_THAT(auth_factor.type(), Eq(AuthFactorType::kKiosk));
  EXPECT_THAT(auth_factor.metadata().metadata,
              VariantWith<auth_factor::KioskMetadata>(_));
}

// Test adding two fingerprint auth factors to the newly created user.
// The first attempt should create a rate-limiter and the second should reuse
// it.
TEST_F(AuthSessionWithUssExperimentTest, AddFingerprint) {
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());
  EXPECT_EQ(AddFirstFingerprintAuthFactor(auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(AddSubsequentFingerprintAuthFactor(auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  // Test and verify.
  std::map<std::string, AuthFactorType> stored_factors =
      auth_factor_manager_.ListAuthFactors(SanitizeUserName(kFakeUsername));
  EXPECT_THAT(
      stored_factors,
      ElementsAre(
          Pair(kFakeFingerprintLabel, AuthFactorType::kFingerprint),
          Pair(kFakeSecondFingerprintLabel, AuthFactorType::kFingerprint)));
}

// Test that PrepareAuthFactor succeeds for fingerprint with the purpose of add.
TEST_F(AuthSessionWithUssExperimentTest, PrepareFingerprintAdd) {
  // Create an AuthSession and add a mock for a successful auth block prepare.
  auto auth_session = std::make_unique<AuthSession>(
      AuthSession::Params{
          .username = kFakeUsername,
          .is_ephemeral_user = false,
          .intent = AuthIntent::kVerifyOnly,
          .timeout_timer = std::make_unique<base::WallClockTimer>(),
          .auth_factor_status_update_timer =
              std::make_unique<base::WallClockTimer>(),
          .user_exists = true,
          .auth_factor_map = AuthFactorMap(),
          .migrate_to_user_secret_stash = false},
      backing_apis_);
  EXPECT_CALL(*bio_processor_, StartEnrollSession(_))
      .WillOnce([](auto&& callback) { std::move(callback).Run(true); });

  // Test.
  TestFuture<CryptohomeStatus> prepare_future;
  user_data_auth::PrepareAuthFactorRequest request;
  request.set_auth_session_id(auth_session->serialized_token());
  request.set_auth_factor_type(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  request.set_purpose(user_data_auth::PURPOSE_ADD_AUTH_FACTOR);
  auth_session->PrepareAuthFactor(request, prepare_future.GetCallback());
  auth_session.reset();

  // Verify.
  ASSERT_THAT(prepare_future.Get(), IsOk());
}

// Test adding two fingerprint auth factors and authenticating them.
TEST_F(AuthSessionWithUssExperimentTest, AddFingerprintAndAuth) {
  const brillo::SecureBlob kFakeAuthPin(32, 1), kFakeAuthSecret(32, 2);
  auto mock_le_manager = std::make_unique<MockLECredentialManager>();
  MockLECredentialManager* mock_le_manager_ptr = mock_le_manager.get();
  crypto_.set_le_manager_for_testing(std::move(mock_le_manager));
  // Setup.
  AuthSession auth_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = false,
       .auth_factor_map = AuthFactorMap(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);

  // Creating the user.
  EXPECT_TRUE(auth_session.OnUserCreated().ok());
  EXPECT_TRUE(auth_session.has_user_secret_stash());
  EXPECT_EQ(AddFirstFingerprintAuthFactor(auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(AddSubsequentFingerprintAuthFactor(auth_session),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  EXPECT_CALL(auth_block_utility_, GetAuthBlockTypeFromState(_))
      .WillRepeatedly(Return(AuthBlockType::kFingerprint));
  EXPECT_CALL(auth_block_utility_, SelectAuthFactorWithAuthBlock(
                                       AuthBlockType::kFingerprint, _, _, _))
      .WillOnce([&](AuthBlockType auth_block_type, const AuthInput& auth_input,
                    std::vector<AuthFactor> auth_factors,
                    AuthBlock::SelectFactorCallback select_callback) {
        ASSERT_TRUE(auth_input.rate_limiter_label.has_value());
        EXPECT_EQ(auth_input.rate_limiter_label.value(), kFakeRateLimiterLabel);
        EXPECT_EQ(auth_factors.size(), 2);

        AuthInput ret_auth_input{
            .user_input = kFakeAuthPin,
            .fingerprint_auth_input =
                FingerprintAuthInput{
                    .auth_secret = kFakeAuthSecret,
                },
        };

        // Assume the second auth factor is matched.
        std::move(select_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), ret_auth_input,
                 auth_factors[1]);
      });
  EXPECT_CALL(auth_block_utility_,
              DeriveKeyBlobsWithAuthBlock(AuthBlockType::kFingerprint, _, _, _))
      .WillOnce([&](AuthBlockType auth_block_type, const AuthInput& auth_input,
                    const AuthBlockState& auth_state,
                    AuthBlock::DeriveCallback derive_callback) {
        ASSERT_TRUE(auth_input.user_input.has_value());
        ASSERT_TRUE(auth_input.fingerprint_auth_input.has_value());
        ASSERT_TRUE(auth_input.fingerprint_auth_input->auth_secret.has_value());
        EXPECT_EQ(auth_input.user_input.value(), kFakeAuthPin);
        EXPECT_EQ(auth_input.fingerprint_auth_input->auth_secret.value(),
                  kFakeAuthSecret);
        ASSERT_TRUE(std::holds_alternative<FingerprintAuthBlockState>(
            auth_state.state));
        auto& state = std::get<FingerprintAuthBlockState>(auth_state.state);
        EXPECT_EQ(state.template_id, kFakeSecondRecordId);

        auto key_blobs = std::make_unique<KeyBlobs>();
        key_blobs->vkk_key = brillo::SecureBlob(kFakeSecondVkkKey);

        std::move(derive_callback)
            .Run(OkStatus<CryptohomeCryptoError>(), std::move(key_blobs),
                 std::nullopt);
      });
  // Set expectations that rate-limiter and fingerprint credential leaves with
  // non-zero wrong auth attempts will be reset after a successful
  // authentication.
  EXPECT_CALL(*mock_le_manager_ptr, GetWrongAuthAttempts(kFakeRateLimiterLabel))
      .WillOnce(Return(1));
  EXPECT_CALL(*mock_le_manager_ptr, GetWrongAuthAttempts(kFakeFpLabel))
      .WillOnce(Return(1));
  EXPECT_CALL(*mock_le_manager_ptr, GetWrongAuthAttempts(kFakeSecondFpLabel))
      .WillOnce(Return(0));
  EXPECT_CALL(*mock_le_manager_ptr,
              ResetCredential(kFakeRateLimiterLabel,
                              brillo::SecureBlob(kFakeResetSecret),
                              /*strong_reset=*/false));
  EXPECT_CALL(
      *mock_le_manager_ptr,
      ResetCredential(kFakeFpLabel, brillo::SecureBlob(kFakeResetSecret),
                      /*strong_reset=*/false));
  EXPECT_CALL(*mock_le_manager_ptr, ResetCredential(kFakeSecondFpLabel, _, _))
      .Times(0);

  // Test.
  std::string auth_factor_labels[] = {kFakeFingerprintLabel,
                                      kFakeSecondFingerprintLabel};
  user_data_auth::AuthInput auth_input_proto;
  auth_input_proto.mutable_fingerprint_input();
  AuthSession verify_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kVerifyOnly,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AfMapBuilder()
                              .WithUss()
                              .AddCopiesFromMap(auth_session.auth_factor_map())
                              .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  TestFuture<CryptohomeStatus> verify_future;
  verify_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                        verify_future.GetCallback());
  AuthSession decrypt_session(
      {.username = kFakeUsername,
       .is_ephemeral_user = false,
       .intent = AuthIntent::kDecrypt,
       .timeout_timer = std::make_unique<base::WallClockTimer>(),
       .auth_factor_status_update_timer =
           std::make_unique<base::WallClockTimer>(),
       .user_exists = true,
       .auth_factor_map = AfMapBuilder()
                              .WithUss()
                              .AddCopiesFromMap(auth_session.auth_factor_map())
                              .Consume(),
       .migrate_to_user_secret_stash = false},
      backing_apis_);
  TestFuture<CryptohomeStatus> decrypt_future;
  decrypt_session.AuthenticateAuthFactor(auth_factor_labels, auth_input_proto,
                                         decrypt_future.GetCallback());

  // Verify.
  EXPECT_THAT(verify_future.Get(), IsOk());
  EXPECT_EQ(verify_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(verify_session.authorized_intents(),
              UnorderedElementsAre(AuthIntent::kVerifyOnly));
  EXPECT_THAT(decrypt_future.Get(), NotOk());
  EXPECT_EQ(decrypt_session.status(),
            AuthStatus::kAuthStatusFurtherFactorRequired);
  EXPECT_THAT(decrypt_session.authorized_intents(), IsEmpty());
}

}  // namespace cryptohome
