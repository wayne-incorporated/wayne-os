// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_CONSTANTS_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_CONSTANTS_H_

#include <brillo/secure_blob.h>

namespace cryptohome {

// Number of random bytes that the generated salt for challenge-protected
// credentials will contain. Note that the resulting salt size will be equal to
// the sum of this constant and the length of the constant returned by
// GetChallengeCredentialsSaltConstantPrefix().
extern const int kChallengeCredentialsSaltRandomByteCount;

// Returns the constant sequence of bytes that should be used as a prefix for
// the salt for challenge-protected credentials. This is used for domain
// segregation purposes: i.e., to prevent signatures of these salt values from
// being even theoretically useful for compromising some other protocol that
// uses the same cryptographic key (e.g., TLS).
const brillo::Blob& GetChallengeCredentialsSaltConstantPrefix();

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_CONSTANTS_H_
