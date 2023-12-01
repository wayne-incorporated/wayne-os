// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/error/cryptohome_tpm_error.h"

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <libhwsec/error/tpm_retry_action.h>

#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"

namespace cryptohome {

namespace error {

namespace {

using hwsec_foundation::status::NewStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

// PopulateActionFromRetry is a helper function that converts the libhwsec
// TPMRetryAction into CryptohomeError's Action.
ErrorActionSet PopulateActionFromRetry(const hwsec::TPMRetryAction retry) {
  switch (retry) {
    case hwsec::TPMRetryAction::kReboot:
      return ErrorActionSet({PossibleAction::kReboot});
    case hwsec::TPMRetryAction::kCommunication:
    case hwsec::TPMRetryAction::kSession:
    case hwsec::TPMRetryAction::kLater:
      return ErrorActionSet({PossibleAction::kRetry, PossibleAction::kReboot});
    case hwsec::TPMRetryAction::kDefend:
      return ErrorActionSet(PrimaryAction::kTpmLockout);
    case hwsec::TPMRetryAction::kUserAuth:
      return ErrorActionSet({PossibleAction::kAuth});
    case hwsec::TPMRetryAction::kNoRetry:
    case hwsec::TPMRetryAction::kEllipticCurveScalarOutOfRange:
    case hwsec::TPMRetryAction::kUserPresence:
    case hwsec::TPMRetryAction::kSpaceNotFound:
      return ErrorActionSet({PossibleAction::kDevCheckUnexpectedState});
    case hwsec::TPMRetryAction::kNone:
      return NoErrorAction();
  }
}

StatusChain<CryptohomeTPMError> FromTPMErrorBase(
    StatusChain<hwsec::TPMErrorBase> status) {
  if (status.ok()) {
    return OkStatus<CryptohomeTPMError>();
  }

  // Status chain currently doesn't offer a way to get the last element of the
  // stack, so we'll need to iterate through it.
  std::optional<CryptohomeError::ErrorLocation> loc;
  for (const auto& err : status.const_range()) {
    loc = err.UnifiedErrorCode();
  }

  CHECK(loc.has_value());

  // Populate the retry actions and status string.
  auto retry = status->ToTPMRetryAction();
  ErrorActionSet actual_actions = PopulateActionFromRetry(retry);
  std::string loc_str =
      base::StringPrintf("(%s)", status.ToFullString().c_str());

  return NewStatus<CryptohomeTPMError>(
      CryptohomeError::ErrorLocationPair(loc.value(), std::move(loc_str)),
      std::move(actual_actions), retry, std::nullopt);
}

}  // namespace

CryptohomeTPMError::CryptohomeTPMError(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const hwsec::TPMRetryAction retry,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : CryptohomeCryptoError(
          loc, actions, TpmAuthBlockUtils::TPMRetryActionToCrypto(retry), ec),
      retry_(retry) {}

StatusChain<CryptohomeTPMError> CryptohomeTPMError::MakeStatusTrait::operator()(
    StatusChain<hwsec::TPMErrorBase> status) {
  return FromTPMErrorBase(std::move(status));
}

}  // namespace error

}  // namespace cryptohome
