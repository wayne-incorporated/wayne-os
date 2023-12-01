// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/error/cryptohome_crypto_error.h"

#include <memory>
#include <set>
#include <string>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/storage/mount_utils.h"

using hwsec_foundation::status::NewStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace error {

CryptohomeCryptoError::MakeStatusTrait::Unactioned::Unactioned(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : loc_(loc), actions_(actions), ec_(ec) {}

StatusChain<CryptohomeCryptoError>
CryptohomeCryptoError::MakeStatusTrait::Unactioned::Wrap(
    hwsec_foundation::status::StatusChain<CryptohomeCryptoError> status
    [[clang::param_typestate(unconsumed)]]  //
    [[clang::return_typestate(consumed)]]) && {
  return NewStatus<CryptohomeCryptoError>(loc_, std::move(actions_),
                                          status->local_crypto_error(), ec_)
      .Wrap(std::move(status));
}

CryptohomeCryptoError::MakeStatusTrait::Unactioned
CryptohomeCryptoError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeCryptoError::MakeStatusTrait::Unactioned(
      loc, std::move(actions), ec);
}

CryptohomeCryptoError::MakeStatusTrait::Unactioned
CryptohomeCryptoError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeCryptoError::MakeStatusTrait::Unactioned(
      loc, NoErrorAction(), ec);
}

StatusChain<CryptohomeCryptoError>
CryptohomeCryptoError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const CryptoError crypto_err,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return NewStatus<CryptohomeCryptoError>(loc, std::move(actions), crypto_err,
                                          ec);
}

CryptohomeCryptoError::CryptohomeCryptoError(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const CryptoError crypto_error,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : CryptohomeMountError(
          std::move(loc),
          actions,
          CryptoErrorToMountError(crypto_error),
          ec.has_value() ? ec
                         : std::optional<user_data_auth::CryptohomeErrorCode>(
                               MountErrorToCryptohomeError(
                                   CryptoErrorToMountError(crypto_error)))),
      crypto_error_(crypto_error) {}

}  // namespace error

}  // namespace cryptohome
