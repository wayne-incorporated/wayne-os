// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_LOCATION_UTILS_H_
#define CRYPTOHOME_ERROR_LOCATION_UTILS_H_

#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/locations.h"

#include <string>
#include <utility>

namespace cryptohome {

namespace error {

// ErrorLocationSpecifier should be based on the ErrorLocation type to avoid
// down/up casting.
static_assert(
    std::is_same_v<
        ::cryptohome::error::CryptohomeError::ErrorLocation,
        std::underlying_type_t<::cryptohome::error::ErrorLocationSpecifier>>,
    "ErrorLocationSpecifier is different from error location");

// CRYPTOHOME_ERR_LOC() is a macro that helps the preprocessor utility identify
// use of error code.
// Note that this takes a enum in the ErrorLocationSpecifier enum class, and
// converts it to the integer accepted by CryptohomeError. See CryptohomeError
// class on why we need int vs enum.
#define CRYPTOHOME_ERR_LOC(x)                                           \
  (::cryptohome::error::CryptohomeError::ErrorLocationPair(             \
      static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>( \
          ::cryptohome::error::ErrorLocationSpecifier::x),              \
      std::string(#x)))

}  // namespace error

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_LOCATION_UTILS_H_
