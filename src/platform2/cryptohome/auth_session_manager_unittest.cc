// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_session_manager.h"

#include <memory>
#include <string>
#include <utility>

#include <base/test/task_environment.h>
#include <base/unguessable_token.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>

#include "cryptohome/auth_blocks/mock_auth_block_utility.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_keyset_management.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_session/user_session_map.h"

using base::test::TaskEnvironment;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Eq;
using ::testing::IsNull;
using testing::NiceMock;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;

namespace cryptohome {

class AuthSessionManagerTest : public ::testing::Test {
 public:
  AuthSessionManagerTest() = default;
  ~AuthSessionManagerTest() override = default;
  AuthSessionManagerTest(const AuthSessionManagerTest&) = delete;
  AuthSessionManagerTest& operator=(AuthSessionManagerTest&) = delete;
  void SetUp() override {
    auth_session_manager_.set_features(&features_.async);
  }

 protected:
  const Username kUsername{"foo@example.com"};

  TaskEnvironment task_environment_{
      TaskEnvironment::TimeSource::MOCK_TIME,
      TaskEnvironment::ThreadPoolExecutionMode::QUEUED};
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
  FakeFeaturesForTesting features_;
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

  AuthSessionManager auth_session_manager_{&crypto_,
                                           &platform_,
                                           &user_session_map_,
                                           &keyset_management_,
                                           &auth_block_utility_,
                                           &auth_factor_driver_manager_,
                                           &auth_factor_manager_,
                                           &user_secret_stash_storage_,
                                           &user_metadata_reader_};
};

TEST_F(AuthSessionManagerTest, CreateFindRemove) {
  base::UnguessableToken token;
  // Start scope for first InUseAuthSession
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_.CreateAuthSession(kUsername, 0,
                                                AuthIntent::kDecrypt);
    ASSERT_TRUE(auth_session_status.ok());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_THAT(auth_session, NotNull());
    token = auth_session->token();

    // FindAuthSession on the same token doesn't work, the actual session is
    // owned by auth_session_status.
    InUseAuthSession in_use_auth_session =
        auth_session_manager_.FindAuthSession(token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
    // Scope ends here to free the InUseAuthSession and return it to
    // AuthSessionManager.
  }

  // After InUseAuthSession is freed, then AuthSessionManager can operate on the
  // token and remove it.
  EXPECT_TRUE(auth_session_manager_.RemoveAuthSession(token));
  InUseAuthSession in_use_auth_session =
      auth_session_manager_.FindAuthSession(token);
  ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());

  // Repeat with serialized_token overload.
  std::string serialized_token;
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_.CreateAuthSession(kUsername, 0,
                                                AuthIntent::kDecrypt);
    ASSERT_TRUE(auth_session_status.ok());
    AuthSession* auth_session = auth_session_status.value().Get();
    serialized_token = auth_session->serialized_token();
    in_use_auth_session =
        auth_session_manager_.FindAuthSession(serialized_token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
  }

  // Should succeed now that AuthSessionManager owns the AuthSession.
  EXPECT_TRUE(auth_session_manager_.RemoveAuthSession(serialized_token));
  in_use_auth_session = auth_session_manager_.FindAuthSession(serialized_token);
  ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
}

TEST_F(AuthSessionManagerTest, CreateExpire) {
  base::UnguessableToken token;

  // Create and set up an auth session, setting it to authenticated so that it
  // can eventually get expired.
  {
    CryptohomeStatusOr<InUseAuthSession> auth_session_status =
        auth_session_manager_.CreateAuthSession(kUsername, 0,
                                                AuthIntent::kDecrypt);
    ASSERT_TRUE(auth_session_status.ok());
    AuthSession* auth_session = auth_session_status.value().Get();
    ASSERT_THAT(auth_session, NotNull());
    token = auth_session->token();

    InUseAuthSession in_use_auth_session =
        auth_session_manager_.FindAuthSession(token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());

    EXPECT_TRUE(auth_session->OnUserCreated().ok());
    EXPECT_EQ(auth_session->status(), AuthStatus::kAuthStatusAuthenticated);
  }

  // Before expiration we should be able to look up the session again.
  {
    InUseAuthSession in_use_auth_session =
        auth_session_manager_.FindAuthSession(token);
    ASSERT_TRUE(in_use_auth_session.AuthSessionStatus().ok());
  }

  // This should expire the session.
  task_environment_.FastForwardUntilNoTasksRemain();

  // After expiration the session should be gone.
  {
    InUseAuthSession in_use_auth_session =
        auth_session_manager_.FindAuthSession(token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
  }
}

TEST_F(AuthSessionManagerTest, AddFindRemove) {
  base::UnguessableToken token;

  // Start scope for first InUseAuthSession
  {
    auto created_auth_session = std::make_unique<AuthSession>(
        AuthSession::Params{
            .username = kUsername,
            .is_ephemeral_user = false,
            .intent = AuthIntent::kDecrypt,
            .timeout_timer = std::make_unique<base::WallClockTimer>(),
            .auth_factor_status_update_timer =
                std::make_unique<base::WallClockTimer>(),
            .user_exists = false,
            .auth_factor_map = AuthFactorMap(),
            .migrate_to_user_secret_stash = false},
        backing_apis_);
    auto* created_auth_session_ptr = created_auth_session.get();

    InUseAuthSession auth_session =
        auth_session_manager_.AddAuthSession(std::move(created_auth_session));
    ASSERT_THAT(auth_session.Get(), Eq(created_auth_session_ptr));
    token = auth_session->token();

    // FindAuthSession on the same token doesn't work, the actual session is
    // owned by |auth_session|.
    InUseAuthSession in_use_auth_session =
        auth_session_manager_.FindAuthSession(token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
    // Scope ends here to free the InUseAuthSession and return it to
    // AuthSessionManager.
  }

  // After InUseAuthSession is freed, then AuthSessionManager can operate on the
  // token and remove it.
  EXPECT_TRUE(auth_session_manager_.RemoveAuthSession(token));
  InUseAuthSession in_use_auth_session =
      auth_session_manager_.FindAuthSession(token);
  ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());

  // Repeat with serialized_token overload.
  std::string serialized_token;
  {
    auto created_auth_session = std::make_unique<AuthSession>(
        AuthSession::Params{
            .username = kUsername,
            .is_ephemeral_user = false,
            .intent = AuthIntent::kDecrypt,
            .timeout_timer = std::make_unique<base::WallClockTimer>(),
            .auth_factor_status_update_timer =
                std::make_unique<base::WallClockTimer>(),
            .user_exists = false,
            .auth_factor_map = AuthFactorMap(),
            .migrate_to_user_secret_stash = false},
        backing_apis_);
    auto* created_auth_session_ptr = created_auth_session.get();

    InUseAuthSession auth_session =
        auth_session_manager_.AddAuthSession(std::move(created_auth_session));
    ASSERT_THAT(auth_session.Get(), Eq(created_auth_session_ptr));

    serialized_token = auth_session->serialized_token();
    in_use_auth_session =
        auth_session_manager_.FindAuthSession(serialized_token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
  }

  // Should succeed now that AuthSessionManager owns the AuthSession.
  EXPECT_TRUE(auth_session_manager_.RemoveAuthSession(serialized_token));
  in_use_auth_session = auth_session_manager_.FindAuthSession(serialized_token);
  ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
}

TEST_F(AuthSessionManagerTest, RemoveNonExisting) {
  EXPECT_FALSE(
      auth_session_manager_.RemoveAuthSession(base::UnguessableToken()));
  EXPECT_FALSE(auth_session_manager_.RemoveAuthSession("non-existing-token"));
}

TEST_F(AuthSessionManagerTest, FlagPassing) {
  // Arrange.
  CryptohomeStatusOr<InUseAuthSession> auth_session_status =
      auth_session_manager_.CreateAuthSession(kUsername, 0,
                                              AuthIntent::kDecrypt);
  ASSERT_TRUE(auth_session_status.ok());
  AuthSession* auth_session = auth_session_status.value().Get();
  CryptohomeStatusOr<InUseAuthSession> ephemral_auth_session_status =
      auth_session_manager_.CreateAuthSession(
          kUsername, user_data_auth::AUTH_SESSION_FLAGS_EPHEMERAL_USER,
          AuthIntent::kDecrypt);
  ASSERT_TRUE(ephemral_auth_session_status.ok());
  AuthSession* ephemeral_auth_session =
      ephemral_auth_session_status.value().Get();

  // Assert
  EXPECT_FALSE(auth_session->ephemeral_user());
  EXPECT_TRUE(ephemeral_auth_session->ephemeral_user());
}

TEST_F(AuthSessionManagerTest, IntentPassing) {
  // Arrange.
  CryptohomeStatusOr<InUseAuthSession> decryption_auth_session_status =
      auth_session_manager_.CreateAuthSession(kUsername, 0,
                                              AuthIntent::kDecrypt);
  ASSERT_TRUE(decryption_auth_session_status.ok());
  AuthSession* decryption_auth_session =
      decryption_auth_session_status.value().Get();
  CryptohomeStatusOr<InUseAuthSession> verification_auth_session_status =
      auth_session_manager_.CreateAuthSession(kUsername, 0,
                                              AuthIntent::kVerifyOnly);
  ASSERT_TRUE(verification_auth_session_status.ok());
  AuthSession* verification_auth_session =
      verification_auth_session_status.value().Get();

  // Assert.
  EXPECT_EQ(decryption_auth_session->auth_intent(), AuthIntent::kDecrypt);
  EXPECT_EQ(verification_auth_session->auth_intent(), AuthIntent::kVerifyOnly);
}

TEST_F(AuthSessionManagerTest, AddFindUnMount) {
  base::UnguessableToken token;

  // Start scope for first InUseAuthSession
  {
    auto created_auth_session = std::make_unique<AuthSession>(
        AuthSession::Params{
            .username = kUsername,
            .is_ephemeral_user = false,
            .intent = AuthIntent::kDecrypt,
            .timeout_timer = std::make_unique<base::WallClockTimer>(),
            .auth_factor_status_update_timer =
                std::make_unique<base::WallClockTimer>(),
            .user_exists = false,
            .auth_factor_map = AuthFactorMap(),
            .migrate_to_user_secret_stash = false},
        backing_apis_);
    auto* created_auth_session_ptr = created_auth_session.get();

    InUseAuthSession auth_session =
        auth_session_manager_.AddAuthSession(std::move(created_auth_session));
    ASSERT_THAT(auth_session.Get(), Eq(created_auth_session_ptr));
    token = auth_session->token();

    // FindAuthSession on the same token doesn't work, the actual session is
    // owned by |auth_session|.
    InUseAuthSession in_use_auth_session =
        auth_session_manager_.FindAuthSession(token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
    // Scope ends here to free the InUseAuthSession and return it to
    // AuthSessionManager.
  }

  // After InUseAuthSession is freed, then AuthSessionManager can operate on the
  // token and remove it.
  EXPECT_TRUE(auth_session_manager_.RemoveAuthSession(token));
  InUseAuthSession in_use_auth_session =
      auth_session_manager_.FindAuthSession(token);
  ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());

  // Repeat with serialized_token overload.
  std::string serialized_token;
  {
    auto created_auth_session = std::make_unique<AuthSession>(
        AuthSession::Params{
            .username = kUsername,
            .is_ephemeral_user = false,
            .intent = AuthIntent::kDecrypt,
            .timeout_timer = std::make_unique<base::WallClockTimer>(),
            .auth_factor_status_update_timer =
                std::make_unique<base::WallClockTimer>(),
            .user_exists = false,
            .auth_factor_map = AuthFactorMap(),
            .migrate_to_user_secret_stash = false},
        backing_apis_);
    auto* created_auth_session_ptr = created_auth_session.get();

    InUseAuthSession auth_session =
        auth_session_manager_.AddAuthSession(std::move(created_auth_session));
    ASSERT_THAT(auth_session.Get(), Eq(created_auth_session_ptr));

    serialized_token = auth_session->serialized_token();
    in_use_auth_session =
        auth_session_manager_.FindAuthSession(serialized_token);
    ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
  }

  // Should succeed now that AuthSessionManager owns the AuthSession.
  auth_session_manager_.RemoveAllAuthSessions();
  in_use_auth_session = auth_session_manager_.FindAuthSession(serialized_token);
  ASSERT_FALSE(in_use_auth_session.AuthSessionStatus().ok());
}

}  // namespace cryptohome
