// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/pin.h"

#include <limits>
#include <utility>
#include <variant>

#include <base/time/time.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/auth_blocks/pin_weaver_auth_block.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {
namespace {

using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::hwsec_foundation::status::MakeStatus;

user_data_auth::LockoutPolicy LockoutPolicyToAuthFactor(
    const std::optional<auth_factor::LockoutPolicy>& policy) {
  if (!policy.has_value()) {
    // This assumption can be made because historically all pins have been
    // attempt limited. When modern pins are enabled they will say time limited
    // explicitly.
    return user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED;
  }
  switch (policy.value()) {
    case auth_factor::LockoutPolicy::TIME_LIMITED:
      return user_data_auth::LOCKOUT_POLICY_TIME_LIMITED;
    // This assumption can be made because historically all pins have been
    // attempt limited. When modern pins are enabled they will say time limited
    // explicitly.
    case auth_factor::LockoutPolicy::NO_LOCKOUT:
    case auth_factor::LockoutPolicy::ATTEMPT_LIMITED:
    case auth_factor::LockoutPolicy::UNKNOWN:
      return user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED;
  }
}

}  // namespace

bool PinAuthFactorDriver::IsSupportedByHardware() const {
  return PinWeaverAuthBlock::IsSupported(*crypto_).ok();
}

bool PinAuthFactorDriver::NeedsResetSecret() const {
  return true;
}

bool PinAuthFactorDriver::NeedsRateLimiter() const {
  return false;
}

bool PinAuthFactorDriver::IsDelaySupported() const {
  return true;
}

CryptohomeStatusOr<base::TimeDelta> PinAuthFactorDriver::GetFactorDelay(
    const ObfuscatedUsername& username, const AuthFactor& factor) const {
  // Do all the error checks to make sure the input is useful.
  if (factor.type() != type()) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocAuthFactorPinGetFactorDelayWrongFactorType),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }
  auto* state =
      std::get_if<PinWeaverAuthBlockState>(&(factor.auth_block_state().state));
  if (!state) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocAuthFactorPinGetFactorDelayInvalidBlockState),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }
  if (!state->le_label) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocAuthFactorPinGetFactorDelayMissingLabel),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }
  // Try and extract the delay from the LE credential manager.
  auto delay_in_seconds =
      crypto_->le_manager()->GetDelayInSeconds(*state->le_label);
  if (!delay_in_seconds.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(kLocAuthFactorPinGetFactorDelayReadFailed))
        .Wrap(std::move(delay_in_seconds).status());
  }
  // Return the extracted time, handling the max value case.
  if (*delay_in_seconds == std::numeric_limits<uint32_t>::max()) {
    return base::TimeDelta::Max();
  } else {
    return base::Seconds(*delay_in_seconds);
  }
}

AuthFactorLabelArity PinAuthFactorDriver::GetAuthFactorLabelArity() const {
  return AuthFactorLabelArity::kSingle;
}

std::optional<user_data_auth::AuthFactor>
PinAuthFactorDriver::TypedConvertToProto(
    const auth_factor::CommonMetadata& common,
    const auth_factor::PinMetadata& typed_metadata) const {
  user_data_auth::AuthFactor proto;
  proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
  proto.mutable_common_metadata()->set_lockout_policy(
      LockoutPolicyToAuthFactor(common.lockout_policy));
  proto.mutable_pin_metadata();
  return proto;
}

}  // namespace cryptohome
