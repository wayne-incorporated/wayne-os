// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_NV_INDEX_AUTHENTICATOR_H_
#define TPM_MANAGER_SERVER_NV_INDEX_AUTHENTICATOR_H_

#include <memory>
#include <string>

#include <trunks/scoped_global_session.h>
#include <trunks/tpm_utility_impl.h>

#include "tpm_manager/server/tpm_status.h"

#include <base/check.h>
#include <base/logging.h>

namespace tpm_manager {

// Enable salting for global session.
inline constexpr bool kGlobalSessionSalted = true;
// Enable encryption for global session.
inline constexpr bool kGlobalSessionEncryption = true;

/*
 * NvIndexAuthenticator is a helper class which hold the needed variable used
 * for creating and holding the ownership of authorization session and
 * released when desturcting.
 *
 * The usage:
 *  NvIndexAuthenticator nvindex_auth(tpm_status_, &trunks_session_,
 *        trunks_factory_);
 * and then call the helper to initialize a session and get delegate when
 * needed.
 *
 * It is used only in tpm2_nvram_impl.cc currently.
 */
class NvIndexAuthenticator {
 public:
  NvIndexAuthenticator(TpmStatus* tpm_status,
                       std::unique_ptr<trunks::HmacSession>* trunks_session,
                       const trunks::TrunksFactory& factory)
      : tpm_status_(tpm_status),
        trunks_factory_(factory),
        trunks_session_(trunks_session),
        password_delegate_(nullptr),
        session_scope_(nullptr) {
    CHECK(tpm_status_);
  }

  trunks::AuthorizationDelegate* GetDirectAuthDelegate(
      const std::string& authorization_value) {
    bool use_hmac_session;
    if (authorization_value.empty()) {
      use_hmac_session = false;
    } else {
      TpmStatus::TpmOwnershipStatus ownership_status;
      if (!tpm_status_->GetTpmOwned(&ownership_status)) {
        LOG(ERROR) << __func__ << ": failed to get tpm ownership status";
        return nullptr;
      }

      use_hmac_session = ownership_status == TpmStatus::kTpmOwned;
    }

    if (use_hmac_session) {
      return SetupHMACSession(authorization_value);
    }

    password_delegate_ =
        trunks_factory_.GetPasswordAuthorization(authorization_value);
    return password_delegate_.get();
  }

  trunks::AuthorizationDelegate* GetOwnerAuthDelegate(
      const std::string& owner_password) {
    TpmStatus::TpmOwnershipStatus ownership_status;
    if (!tpm_status_->GetTpmOwned(&ownership_status)) {
      LOG(ERROR) << __func__ << ": failed to get tpm ownership status";
      return nullptr;
    }

    switch (ownership_status) {
      case TpmStatus::kTpmUnowned:
        password_delegate_ = trunks_factory_.GetPasswordAuthorization("");
        return password_delegate_.get();
      case TpmStatus::kTpmPreOwned:
        password_delegate_ = trunks_factory_.GetPasswordAuthorization(
            trunks::kWellKnownPassword);
        return password_delegate_.get();
      case TpmStatus::kTpmOwned:
      case TpmStatus::kTpmSrkNoAuth:
      case TpmStatus::kTpmDisabled:
        // return error if TPM is owned but the owner_password is not available
        if (owner_password.empty()) {
          // The owner password has been destroyed.
          return nullptr;
        }
        return SetupHMACSession(owner_password);
    }
  }

 private:
  /*
   * helper to initialize the HMAC session
   * return the delegate if initialize successfully. Otherwise, return nullptr.
   */
  trunks::AuthorizationDelegate* SetupHMACSession(
      const std::string& authorization_value) {
    session_scope_ = std::make_unique<trunks::ScopedGlobalHmacSession>(
        &trunks_factory_, kGlobalSessionSalted, kGlobalSessionEncryption,
        trunks_session_);
    if (!*trunks_session_) {
      // Session failure
      return nullptr;
    }
    (*trunks_session_)->SetEntityAuthorizationValue(authorization_value);
    return (*trunks_session_)->GetDelegate();
  }

  TpmStatus* tpm_status_;
  const trunks::TrunksFactory& trunks_factory_;

  std::unique_ptr<trunks::HmacSession>* trunks_session_;
  std::unique_ptr<trunks::AuthorizationDelegate> password_delegate_;
  std::unique_ptr<trunks::ScopedGlobalHmacSession> session_scope_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_NV_INDEX_AUTHENTICATOR_H_
