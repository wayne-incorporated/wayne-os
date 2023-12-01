// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_session_manager.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/notreached.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <libhwsec/status.h>

#include "cryptohome/auth_blocks/auth_block_utility.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/platform.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_secret_stash/user_metadata.h"
#include "cryptohome/user_session/user_session_map.h"

namespace cryptohome {
namespace {

using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;

}  // namespace

AuthSessionManager::AuthSessionManager(
    Crypto* crypto,
    Platform* platform,
    UserSessionMap* user_session_map,
    KeysetManagement* keyset_management,
    AuthBlockUtility* auth_block_utility,
    AuthFactorDriverManager* auth_factor_driver_manager,
    AuthFactorManager* auth_factor_manager,
    UserSecretStashStorage* user_secret_stash_storage,
    UserMetadataReader* user_metadata_reader)
    : crypto_(crypto),
      platform_(platform),
      user_session_map_(user_session_map),
      keyset_management_(keyset_management),
      auth_block_utility_(auth_block_utility),
      auth_factor_driver_manager_(auth_factor_driver_manager),
      auth_factor_manager_(auth_factor_manager),
      user_secret_stash_storage_(user_secret_stash_storage),
      user_metadata_reader_(user_metadata_reader),
      features_(nullptr) {
  // Preconditions
  DCHECK(crypto_);
  DCHECK(platform_);
  DCHECK(user_session_map_);
  DCHECK(keyset_management_);
  DCHECK(auth_block_utility_);
  DCHECK(auth_factor_driver_manager_);
  DCHECK(auth_factor_manager_);
  DCHECK(user_secret_stash_storage_);
  DCHECK(user_metadata_reader_);
}

CryptohomeStatusOr<InUseAuthSession> AuthSessionManager::CreateAuthSession(
    const Username& account_id, uint32_t flags, AuthIntent auth_intent) {
  // Assumption here is that keyset_management_ will outlive this AuthSession.
  std::unique_ptr<AuthSession> auth_session = AuthSession::Create(
      account_id, flags, auth_intent,
      {crypto_, platform_, user_session_map_, keyset_management_,
       auth_block_utility_, auth_factor_driver_manager_, auth_factor_manager_,
       user_secret_stash_storage_, user_metadata_reader_, features_});
  return AddAuthSession(std::move(auth_session));
}

InUseAuthSession AuthSessionManager::AddAuthSession(
    std::unique_ptr<AuthSession> auth_session) {
  // We should never, ever, be able to get a token collision.
  const auto& token = auth_session->token();
  auto iter = auth_sessions_.lower_bound(token);
  DCHECK(iter == auth_sessions_.end() || iter->first != token)
      << "AuthSession token collision";

  // Add an entry to the session map. Note that we're deliberately initializing
  // things into an in-use state by only adding a blank entry in the map.
  auth_sessions_.emplace_hint(iter, token, nullptr);
  InUseAuthSession in_use(*this, /*is_session_active=*/true,
                          std::move(auth_session));

  // Attach the expiration handler to the AuthSession. It's important that we do
  // this after creating the map entry and in_use object because the callback
  // may immediately fire. This should NOT immediately delete the AuthSession
  // object although it may remove the auth_sessions_ entry we just added.
  //
  // Note that it is safe for use to use |Unretained| here because the manager
  // should always outlive all of the sessions it owns.
  in_use->SetOnTimeoutCallback(base::BindOnce(
      &AuthSessionManager::ExpireAuthSession, base::Unretained(this)));

  // Set the AuthFactorStatusUpdate signal handler to the auth session.
  if (auth_factor_status_update_callback_) {
    in_use->SetAuthFactorStatusUpdateCallback(
        base::BindRepeating(auth_factor_status_update_callback_));
    in_use->SendAuthFactorStatusUpdateSignal();
  }

  return in_use;
}

void AuthSessionManager::RemoveAllAuthSessions() {
  auth_sessions_.clear();
}

bool AuthSessionManager::RemoveAuthSession(
    const base::UnguessableToken& token) {
  const auto iter = auth_sessions_.find(token);
  if (iter == auth_sessions_.end())
    return false;
  auth_sessions_.erase(iter);
  return true;
}

bool AuthSessionManager::RemoveAuthSession(
    const std::string& serialized_token) {
  std::optional<base::UnguessableToken> token =
      AuthSession::GetTokenFromSerializedString(serialized_token);
  if (!token.has_value()) {
    LOG(ERROR) << "Unparsable AuthSession token for removal";
    return false;
  }
  return RemoveAuthSession(token.value());
}

void AuthSessionManager::ExpireAuthSession(
    const base::UnguessableToken& token) {
  if (!RemoveAuthSession(token)) {
    // All active auth sessions should be tracked by the manager, so report it
    // if the just-expired session is unknown.
    NOTREACHED() << "Failed to remove expired AuthSession.";
  }
}

InUseAuthSession AuthSessionManager::FindAuthSession(
    const std::string& serialized_token) {
  std::optional<base::UnguessableToken> token =
      AuthSession::GetTokenFromSerializedString(serialized_token);
  if (!token.has_value()) {
    LOG(ERROR) << "Unparsable AuthSession token for find";
    return InUseAuthSession(*this, /*is_session_active=*/false, nullptr);
  }
  return FindAuthSession(token.value());
}

InUseAuthSession AuthSessionManager::FindAuthSession(
    const base::UnguessableToken& token) {
  auto it = auth_sessions_.find(token);
  if (it == auth_sessions_.end()) {
    return InUseAuthSession(*this, /*is_session_active=*/false, nullptr);
  }

  // If the AuthSessionManager doesn't own the AuthSession unique_ptr,
  // then the AuthSession is actively in use for another dbus operation.
  if (!it->second) {
    return InUseAuthSession(*this, /*is_session_active=*/true, nullptr);
  } else {
    // By giving ownership of the unique_ptr we are marking
    // the AuthSession as in active use.
    return InUseAuthSession(*this, /*is_session_active=*/false,
                            std::move(it->second));
  }
}

// Move the unique_ptr back into the AuthSessionManager structure, to mark
// it as available for other dbus operations.
void AuthSessionManager::MarkNotInUse(std::unique_ptr<AuthSession> session) {
  auto it = auth_sessions_.find(session->token());
  if (it == auth_sessions_.end()) {
    return;
  }
  it->second = std::move(session);
}

InUseAuthSession::InUseAuthSession()
    : manager_(nullptr), is_session_active_(false), session_(nullptr) {}

InUseAuthSession::InUseAuthSession(AuthSessionManager& manager,
                                   bool is_session_active,
                                   std::unique_ptr<AuthSession> session)
    : manager_(&manager),
      is_session_active_(is_session_active),
      session_(std::move(session)) {}

InUseAuthSession::InUseAuthSession(InUseAuthSession&& auth_session)
    : manager_(auth_session.manager_),
      is_session_active_(auth_session.is_session_active_),
      session_(std::move(auth_session.session_)) {}

InUseAuthSession& InUseAuthSession::operator=(InUseAuthSession&& auth_session) {
  manager_ = auth_session.manager_;
  is_session_active_ = auth_session.is_session_active_;
  session_ = std::move(auth_session.session_);
  return *this;
}

InUseAuthSession::~InUseAuthSession() {
  if (session_ && manager_) {
    manager_->MarkNotInUse(std::move(session_));
  }
}

CryptohomeStatus InUseAuthSession::AuthSessionStatus() {
  if (!session_) {
    // InUseAuthSession wasn't made with a valid AuthSession unique_ptr
    if (is_session_active_) {
      LOG(ERROR) << "Existing AuthSession is locked in a previous opertaion.";
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocAuthSessionManagerAuthSessionActive),
          ErrorActionSet({PossibleAction::kReboot}),
          user_data_auth::CryptohomeErrorCode::
              CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
    } else {
      LOG(ERROR) << "Invalid AuthSession token provided.";
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocAuthSessionManagerAuthSessionNotFound),
          ErrorActionSet({PossibleAction::kReboot}),
          user_data_auth::CryptohomeErrorCode::
              CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
    }
  } else {
    return OkStatus<CryptohomeError>();
  }
}

AuthSession* InUseAuthSession::Get() {
  return session_.get();
}

void AuthSessionManager::SetAuthFactorStatusUpdateCallback(
    const AuthFactorStatusUpdateCallback& callback) {
  auth_factor_status_update_callback_ = callback;
}

}  // namespace cryptohome
