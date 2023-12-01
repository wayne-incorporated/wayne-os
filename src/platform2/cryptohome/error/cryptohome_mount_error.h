// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_CRYPTOHOME_MOUNT_ERROR_H_
#define CRYPTOHOME_ERROR_CRYPTOHOME_MOUNT_ERROR_H_

#include <memory>
#include <set>
#include <string>
#include <utility>

#include <chromeos/dbus/service_constants.h>
#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {

namespace error {

// This class is a CryptohomeError that holds an extra MountError.
// It is designed for situations that needs the content of the MountError and
// still be compatible with CryptohomeError.
class CryptohomeMountError : public CryptohomeError {
 public:
  struct MakeStatusTrait : public hwsec_foundation::status::AlwaysNotOk {
    // |MountErrorUnset| represents an intermediate state, when we create an
    // error without fully specifying that error. That allows to require Wrap to
    // be called, or otherwise a type mismatch error will be raised.
    class MountErrorUnset {
     public:
      MountErrorUnset(
          const ErrorLocationPair& loc,
          const ErrorActionSet& actions,
          const std::optional<user_data_auth::CryptohomeErrorCode> ec);

      [[clang::return_typestate(unconsumed)]]  //
      hwsec_foundation::status::StatusChain<CryptohomeMountError>
      Wrap(hwsec_foundation::status::StatusChain<CryptohomeMountError> status
           [[clang::param_typestate(unconsumed)]]  //
           [[clang::return_typestate(consumed)]]) &&;

     private:
      const ErrorLocationPair loc_;
      const ErrorActionSet actions_;
      const std::optional<user_data_auth::CryptohomeErrorCode> ec_;
    };

    // |ActionsUnset| represents an intermediate state, when we create an error
    // without fully specifying that error. This is similar to |MountErrorUnset|
    // but MountError is supplied instead of Action. This is needed so that
    // we've more freedom in the type accepted in Wrap.
    class ActionsUnset {
     public:
      ActionsUnset(const ErrorLocationPair& loc,
                   const MountError mount_error,
                   const std::optional<user_data_auth::CryptohomeErrorCode> ec);

      [[clang::return_typestate(unconsumed)]]  //
      hwsec_foundation::status::StatusChain<CryptohomeMountError>
      Wrap(hwsec_foundation::status::StatusChain<CryptohomeError> status
           [[clang::param_typestate(unconsumed)]]  //
           [[clang::return_typestate(consumed)]]) &&;

     private:
      const ErrorLocationPair loc_;
      const MountError mount_error_;
      const std::optional<user_data_auth::CryptohomeErrorCode> ec_;
    };

    // Creates a stub which has to wrap another |CryptohomeMountError| to
    // become a valid status chain.
    MountErrorUnset operator()(
        const ErrorLocationPair& loc,
        const ErrorActionSet& actions,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);

    // Creates a stub which has to wrap another |CryptohomeMountError| to
    // become a valid status chain. This variant is without ErrorAction and
    // MountError.
    MountErrorUnset operator()(
        const ErrorLocationPair& loc,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);

    // Creates a stub which has to wrap another |CryptohomeMountError| to
    // become a valid status chain. This variant is without ErrorAction.
    ActionsUnset operator()(
        const ErrorLocationPair& loc,
        const MountError mount_err,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);

    // Create an error directly.
    hwsec_foundation::status::StatusChain<CryptohomeMountError> operator()(
        const ErrorLocationPair& loc,
        const ErrorActionSet& actions,
        const MountError mount_err,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);
  };

  // The copyable/movable aspect of this class depends on the base
  // hwsec_foundation::status::Error class. See that class for more info.

  // If the legacy error code is not supplied, it is automatically converted.
  CryptohomeMountError(
      const ErrorLocationPair& loc,
      const ErrorActionSet& actions,
      const MountError mount_err,
      const std::optional<user_data_auth::CryptohomeErrorCode> ec);

  MountError mount_error() const { return mount_error_; }

 private:
  MountError mount_error_;
};

}  // namespace error

// Define an alias in the cryptohome namespace for easier access.
using MountStatus =
    hwsec_foundation::status::StatusChain<error::CryptohomeMountError>;
template <typename _Et>
using MountStatusOr =
    hwsec_foundation::status::StatusChainOr<_Et, error::CryptohomeMountError>;

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_CRYPTOHOME_MOUNT_ERROR_H_
