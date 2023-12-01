// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_PREPARE_PURPOSE_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_PREPARE_PURPOSE_H_

namespace cryptohome {

// A prepare purpose specifies the operation that can be performed after
// a successful call to PrepareAuthFactor().
enum class AuthFactorPreparePurpose {
  // Purpose to add an auth factor.
  kPrepareAddAuthFactor,
  // Purpose to authenticate an auth factor.
  kPrepareAuthenticateAuthFactor,
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_PREPARE_PURPOSE_H_
