// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/error/cryptohome_error.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_util.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

using hwsec_foundation::status::NewStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace error {

CryptohomeError::MakeStatusTrait::Unactioned::Unactioned(
    const ErrorLocationPair& loc,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : loc_(loc), ec_(ec) {}

CryptohomeError::MakeStatusTrait::Unactioned
CryptohomeError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return CryptohomeError::MakeStatusTrait::Unactioned(loc, ec);
}

StatusChain<CryptohomeError> CryptohomeError::MakeStatusTrait::Unactioned::Wrap(
    hwsec_foundation::status::StatusChain<CryptohomeError> status
    [[clang::param_typestate(unconsumed)]]  //
    [[clang::return_typestate(consumed)]]) && {
  return NewStatus<CryptohomeError>(
             loc_, NoErrorAction(),
             ec_.has_value() ? ec_ : status->local_legacy_error())
      .Wrap(std::move(status));
}

StatusChain<CryptohomeError> CryptohomeError::MakeStatusTrait::operator()(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec) {
  return NewStatus<CryptohomeError>(loc, std::move(actions), ec);
}

CryptohomeError::CryptohomeError(
    const ErrorLocationPair& loc,
    const ErrorActionSet& actions,
    const std::optional<user_data_auth::CryptohomeErrorCode> ec)
    : loc_(std::move(loc)), actions_(actions), ec_(ec) {}

std::string CryptohomeError::ToString() const {
  std::stringstream ss;
  ss << "Loc: " << loc_.name() << "/" << loc_.location();
  return ss.str();
}

}  // namespace error

}  // namespace cryptohome
