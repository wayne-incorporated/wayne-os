// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/credential_verifier.h"

#include <utility>

namespace cryptohome {

bool SyncCredentialVerifier::Verify(const AuthInput& input) const {
  return VerifySync(input).ok();
}

void SyncCredentialVerifier::Verify(const AuthInput& input,
                                    StatusCallback callback) const {
  std::move(callback).Run(VerifySync(input));
}

bool AsyncCredentialVerifier::Verify(const AuthInput& input) const {
  return false;
}

void AsyncCredentialVerifier::Verify(const AuthInput& input,
                                     StatusCallback callback) const {
  VerifyAsync(input, std::move(callback));
}

}  // namespace cryptohome
