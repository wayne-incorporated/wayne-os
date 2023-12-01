// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_UTILITIES_H_
#define CRYPTOHOME_ERROR_UTILITIES_H_

#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {

namespace error {

// Returns true iff any error in the chain contains the given
// action.
template <typename ErrorType>
bool PrimaryActionIs(
    const hwsec_foundation::status::StatusChain<ErrorType>& error,
    const PrimaryAction action);

template <typename ErrorType>
bool PossibleActionsInclude(
    const hwsec_foundation::status::StatusChain<ErrorType>& error,
    const PossibleAction action);

}  // namespace error

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_UTILITIES_H_
