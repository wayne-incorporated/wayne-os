// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_CRYPTOHOME_LE_CRED_ERROR_H_
#define CRYPTOHOME_ERROR_CRYPTOHOME_LE_CRED_ERROR_H_

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include <chromeos/dbus/service_constants.h>
#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/le_credential_error.h"

namespace cryptohome {

namespace error {

// This class is a CryptohomeError that holds an extra LECredError.
// It is designed for situations that needs the content of the LECredError and
// still be compatible with CryptohomeError.
class CryptohomeLECredError : public CryptohomeCryptoError {
 public:
  struct MakeStatusTrait : public hwsec_foundation::status::AlwaysNotOk {
    // |Unactioned| represents an intermediate state, when we create an error
    // without fully specifying that error. That allows to require Wrap to be
    // called, or otherwise a type mismatch error will be raised.
    class Unactioned {
     public:
      Unactioned(const ErrorLocationPair& loc,
                 const ErrorActionSet& actions,
                 const std::optional<user_data_auth::CryptohomeErrorCode> ec);

      [[clang::return_typestate(unconsumed)]]  //
      hwsec_foundation::status::StatusChain<CryptohomeLECredError>
      Wrap(hwsec_foundation::status::StatusChain<CryptohomeLECredError> status
           [[clang::param_typestate(unconsumed)]]  //
           [[clang::return_typestate(consumed)]]) &&;

     private:
      const ErrorLocationPair loc_;
      const ErrorActionSet actions_;
      const std::optional<user_data_auth::CryptohomeErrorCode> ec_;
    };

    // Creates a stub which has to wrap another |CryptohomeLECredError| to
    // become a valid status chain.
    Unactioned operator()(
        const ErrorLocationPair& loc,
        const ErrorActionSet& actions,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);

    // Creates a stub which has to wrap another |CryptohomeLECredError| to
    // become a valid status chain. This variant is without ErrorAction.
    Unactioned operator()(
        const ErrorLocationPair& loc,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);

    // Create an error directly.
    hwsec_foundation::status::StatusChain<CryptohomeLECredError> operator()(
        const ErrorLocationPair& loc,
        const ErrorActionSet actions,
        const LECredError lecred_err,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);
  };

  // The copyable/movable aspect of this class depends on the base
  // hwsec_foundation::status::Error class. See that class for more info.

  // Direct construction. If ec is std::nullopt, it'll be assigned through
  // conversion from lecred_err.
  CryptohomeLECredError(
      const ErrorLocationPair& loc,
      const ErrorActionSet& actions,
      const LECredError lecred_err,
      const std::optional<user_data_auth::CryptohomeErrorCode> ec);

  LECredError local_lecred_error() const { return lecred_error_; }

 private:
  LECredError lecred_error_;
};

}  // namespace error

// Define an alias in the cryptohome namespace for easier access.
using LECredStatus =
    hwsec_foundation::status::StatusChain<error::CryptohomeLECredError>;
template <typename _Et>
using LECredStatusOr =
    hwsec_foundation::status::StatusChainOr<_Et, error::CryptohomeLECredError>;

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_CRYPTOHOME_LE_CRED_ERROR_H_
