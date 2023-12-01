// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/error/cryptohome_le_cred_error.h"

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

CryptohomeLECredError::MakeStatusTrait::Unactioned::Unactioned(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : loc_(loc), actions_(actions), ec_(ec) {}

StatusChain<CryptohomeLECredError>
CryptohomeLECredError::MakeStatusTrait::Unactioned::Wrap(
    hwsec_foundation::status::StatusChain<CryptohomeLECredError> status
    [[clang::param_typestate(unconsumed)]]  //
    [[clang::return_typestate(consumed)]]) && {
  return NewStatus<CryptohomeLECredError>(loc_, std::move(actions_),
                                          status->local_lecred_error(), ec_)
      .Wrap(std::move(status));
}

CryptohomeLECredError::MakeStatusTrait::Unactioned
CryptohomeLECredError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeLECredError::MakeStatusTrait::Unactioned(
      loc, std::move(actions), ec);
}

CryptohomeLECredError::MakeStatusTrait::Unactioned
CryptohomeLECredError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeLECredError::MakeStatusTrait::Unactioned(
      loc, NoErrorAction(), ec);
}

StatusChain<CryptohomeLECredError>
CryptohomeLECredError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet actions,
    const LECredError lecred_err,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return NewStatus<CryptohomeLECredError>(loc, std::move(actions), lecred_err,
                                          ec);
}

CryptohomeLECredError::CryptohomeLECredError(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const LECredError lecred_error,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : CryptohomeCryptoError(
          std::move(loc), actions, LECredErrorToCryptoError(lecred_error), ec),
      lecred_error_(lecred_error) {}

}  // namespace error

}  // namespace cryptohome
