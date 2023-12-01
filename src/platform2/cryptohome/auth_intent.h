// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_INTENT_H_
#define CRYPTOHOME_AUTH_INTENT_H_

namespace cryptohome {

// An intent specifies the set of operations that can be performed after
// successfully authenticating an Auth Session.
enum class AuthIntent {
  // Intent to decrypt the user's file system keys. Authorizing for this intent
  // allows all privileged operations, e.g., preparing user's vault,
  // adding/updating/removing factors.
  kDecrypt,
  // Intent to simply check whether the authentication succeeds. Authorizing for
  // this intent doesn't allow any privileged operation.
  kVerifyOnly,
  // Intent to unlock the WebAuthn capability. Authorizing for this intent
  // allows the WebAuthn operation.
  kWebAuthn,
};
inline constexpr AuthIntent kAllAuthIntents[] = {
    AuthIntent::kDecrypt,
    AuthIntent::kVerifyOnly,
    AuthIntent::kWebAuthn,
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_INTENT_H_
