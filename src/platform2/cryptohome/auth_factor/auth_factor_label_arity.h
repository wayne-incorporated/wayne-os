// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_LABEL_ARITY_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_LABEL_ARITY_H_

namespace cryptohome {

// List of possible label arities. This indicates how many
// labels can be specified with a given auth factor type during
/// authentication.
enum class AuthFactorLabelArity {
  kNone,
  kSingle,
  kMultiple,
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_LABEL_ARITY_H_
