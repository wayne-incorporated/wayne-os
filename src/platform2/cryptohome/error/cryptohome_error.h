// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_CRYPTOHOME_ERROR_H_
#define CRYPTOHOME_ERROR_CRYPTOHOME_ERROR_H_

#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <libhwsec-foundation/error/error.h>
#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/error/action.h"

namespace cryptohome {

namespace error {

class CryptohomeError : public hwsec_foundation::status::Error {
 public:
  using BaseErrorType = CryptohomeError;

  // Note that while ErrorLocation is represented as an integer, the error
  // location specifier defined in locations.h is its own enum. The reason for
  // this difference is that this integer have to encompasses values greater
  // than the range of the locations specified in locations.h, particularly the
  // codes converted from TPMError and related.
  using ErrorLocation = int64_t;

  // Holder for the string and numerical representation of the error location.
  class ErrorLocationPair {
   public:
    ErrorLocationPair(const ErrorLocation input_loc,
                      const std::string& input_name)
        : loc_(input_loc), name_(input_name) {}

    // This class is copyable or movable with the default copy/move
    // constructor/assigment operator.

    // Getter for the location enum or the name.
    ErrorLocation location() const { return loc_; }
    const std::string& name() const { return name_; }

   private:
    const ErrorLocation loc_;
    const std::string name_;
  };

  struct MakeStatusTrait : public hwsec_foundation::status::AlwaysNotOk {
    // |Unactioned| represents an intermediate state, when we create an error
    // without fully specifying that error. That allows to require Wrap to be
    // called, or otherwise a type mismatch error will be raised.
    class Unactioned {
     public:
      Unactioned(const ErrorLocationPair& loc,
                 const std::optional<user_data_auth::CryptohomeErrorCode> ec);

      [[clang::return_typestate(unconsumed)]]  //
      hwsec_foundation::status::StatusChain<CryptohomeError>
      Wrap(hwsec_foundation::status::StatusChain<CryptohomeError> status
           [[clang::param_typestate(unconsumed)]]  //
           [[clang::return_typestate(consumed)]]) &&;

     private:
      const ErrorLocationPair loc_;
      const std::optional<user_data_auth::CryptohomeErrorCode> ec_;
    };

    // Create a stub with no recommended error action. We need to wrap another
    // |CryptohomeError| for it to become a valid status chain.
    Unactioned operator()(
        const ErrorLocationPair& loc,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);

    // Direct creation.
    hwsec_foundation::status::StatusChain<CryptohomeError> operator()(
        const ErrorLocationPair& loc,
        const ErrorActionSet& actions,
        const std::optional<user_data_auth::CryptohomeErrorCode> ec =
            std::nullopt);
  };

  // Standard constructor taking the error location and actions.
  CryptohomeError(const ErrorLocationPair& loc,
                  const ErrorActionSet& actions,
                  const std::optional<user_data_auth::CryptohomeErrorCode> ec =
                      std::nullopt);

  ~CryptohomeError() override = default;

  // Return the location id in this error.
  ErrorLocation local_location() const { return loc_.location(); }

  // Return the recommended actions in this error (but not the wrapped ones).
  const ErrorActionSet& local_actions() const { return actions_; }

  // Return the legacy error code.
  std::optional<user_data_auth::CryptohomeErrorCode> local_legacy_error()
      const {
    return ec_;
  }

  // If we are wrapping a CryptohomeError - concatenate the error id.
  std::string ToString() const override;

 private:
  // From where was the error triggered?
  ErrorLocationPair loc_;

  // What do we recommend the upper layers do?
  ErrorActionSet actions_;

  // The legacy dbus error code.
  std::optional<user_data_auth::CryptohomeErrorCode> ec_;
};

}  // namespace error

// Define an alias in the cryptohome namespace for easier access.
using CryptohomeStatus =
    hwsec_foundation::status::StatusChain<error::CryptohomeError>;
template <typename _Et>
using CryptohomeStatusOr =
    hwsec_foundation::status::StatusChainOr<_Et, error::CryptohomeError>;

// Define an alias for the callback returning CryptohomeStatus in the cryptohome
// namespace for easier access.
using StatusCallback = base::OnceCallback<void(CryptohomeStatus)>;

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_CRYPTOHOME_ERROR_H_
