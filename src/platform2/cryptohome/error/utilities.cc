// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "cryptohome/error/converter.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_le_cred_error.h"
#include "cryptohome/error/utilities.h"

namespace cryptohome {

namespace error {

template <typename ErrorType>
bool PrimaryActionIs(
    const hwsec_foundation::status::StatusChain<ErrorType>& error,
    PrimaryAction action) {
  std::optional<PrimaryAction> primary;
  PossibleActions possible;
  ActionsFromStack(error, primary, possible);
  return primary.has_value() && primary.value() == action;
}

template <typename ErrorType>
bool PossibleActionsInclude(
    const hwsec_foundation::status::StatusChain<ErrorType>& error,
    PossibleAction action) {
  std::optional<PrimaryAction> primary;
  PossibleActions possible;
  ActionsFromStack(error, primary, possible);
  return possible[action];
}

// Instantiate for common types.
template bool PrimaryActionIs(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& error,
    PrimaryAction action);
template bool PrimaryActionIs(
    const hwsec_foundation::status::StatusChain<CryptohomeCryptoError>& error,
    PrimaryAction action);
template bool PrimaryActionIs(const hwsec_foundation::status::StatusChain<
                                  error::CryptohomeLECredError>& error,
                              PrimaryAction action);
template bool PossibleActionsInclude(
    const hwsec_foundation::status::StatusChain<CryptohomeError>& error,
    PossibleAction action);
template bool PossibleActionsInclude(
    const hwsec_foundation::status::StatusChain<CryptohomeCryptoError>& error,
    PossibleAction action);
template bool PossibleActionsInclude(
    const hwsec_foundation::status::StatusChain<error::CryptohomeLECredError>&
        error,
    PossibleAction action);

}  // namespace error

}  // namespace cryptohome
