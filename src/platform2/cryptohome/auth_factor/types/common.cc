// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/common.h"

#include <utility>

#include <base/time/time.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/auth_blocks/prepare_token.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/username.h"

namespace cryptohome {
namespace {

using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::hwsec_foundation::status::MakeStatus;

}  // namespace

void AfDriverNoPrepare::PrepareForAdd(
    const ObfuscatedUsername& username,
    PreparedAuthFactorToken::Consumer callback) {
  std::move(callback).Run(MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocAuthFactorCommonPrepareForAddUnsupported),
      ErrorActionSet(
          {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

void AfDriverNoPrepare::PrepareForAuthenticate(
    const ObfuscatedUsername& username,
    PreparedAuthFactorToken::Consumer callback) {
  std::move(callback).Run(MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocAuthFactorCommonPrepareForAuthUnsupported),
      ErrorActionSet(
          {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

bool AfDriverFullAuthDecrypt::IsFullAuthAllowed(AuthIntent auth_intent) const {
  return true;
}
bool AfDriverFullAuthUnsupported::IsFullAuthAllowed(
    AuthIntent auth_intent) const {
  return false;
}

CryptohomeStatusOr<base::TimeDelta> AfDriverNoDelay::GetFactorDelay(
    const ObfuscatedUsername& username, const AuthFactor& factor) const {
  return MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocAuthFactorCommonGetFactorDelayUnsupported),
      ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

CryptohomeStatusOr<bool> AfDriverNoExpiration::IsExpired(
    const ObfuscatedUsername& username, const AuthFactor& factor) {
  return MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocAuthFactorCommonIsExpiredUnsupported),
      ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

}  // namespace cryptohome
