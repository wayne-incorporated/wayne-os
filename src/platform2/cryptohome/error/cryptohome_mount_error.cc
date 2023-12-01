// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/error/cryptohome_mount_error.h"

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

CryptohomeMountError::MakeStatusTrait::MountErrorUnset::MountErrorUnset(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : loc_(loc), actions_(actions), ec_(ec) {}

StatusChain<CryptohomeMountError>
CryptohomeMountError::MakeStatusTrait::MountErrorUnset::Wrap(
    hwsec_foundation::status::StatusChain<CryptohomeMountError> status
    [[clang::param_typestate(unconsumed)]]  //
    [[clang::return_typestate(consumed)]]) && {
  return NewStatus<CryptohomeMountError>(loc_, std::move(actions_),
                                         status->mount_error(), ec_)
      .Wrap(std::move(status));
}

CryptohomeMountError::MakeStatusTrait::MountErrorUnset
CryptohomeMountError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeMountError::MakeStatusTrait::MountErrorUnset(
      loc, std::move(actions), ec);
}

CryptohomeMountError::MakeStatusTrait::MountErrorUnset
CryptohomeMountError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeMountError::MakeStatusTrait::MountErrorUnset(
      loc, NoErrorAction(), ec);
}

CryptohomeMountError::MakeStatusTrait::ActionsUnset::ActionsUnset(
    const ErrorLocationPair& loc,
    const MountError mount_error,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : loc_(loc), mount_error_(mount_error), ec_(ec) {}

CryptohomeMountError::MakeStatusTrait::ActionsUnset
CryptohomeMountError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const MountError mount_err,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeMountError::MakeStatusTrait::ActionsUnset(loc, mount_err,
                                                             ec);
}

StatusChain<CryptohomeMountError>
CryptohomeMountError::MakeStatusTrait::ActionsUnset::Wrap(
    hwsec_foundation::status::StatusChain<CryptohomeError> status
    [[clang::param_typestate(unconsumed)]]  //
    [[clang::return_typestate(consumed)]]) && {
  return NewStatus<CryptohomeMountError>(loc_, NoErrorAction(), mount_error_,
                                         ec_)
      .Wrap(std::move(status));
}

StatusChain<CryptohomeMountError>
CryptohomeMountError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const MountError mount_err,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return NewStatus<CryptohomeMountError>(loc, std::move(actions), mount_err,
                                         ec);
}

CryptohomeMountError::CryptohomeMountError(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const MountError mount_error,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : CryptohomeError(std::move(loc),
                      actions,
                      ec.has_value()
                          ? ec
                          : std::optional<user_data_auth::CryptohomeErrorCode>(
                                MountErrorToCryptohomeError(mount_error))),
      mount_error_(mount_error) {}

}  // namespace error

}  // namespace cryptohome
