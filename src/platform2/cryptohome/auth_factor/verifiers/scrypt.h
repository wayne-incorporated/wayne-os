// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_VERIFIERS_SCRYPT_H_
#define CRYPTOHOME_AUTH_FACTOR_VERIFIERS_SCRYPT_H_

#include <memory>
#include <string>

#include <brillo/secure_blob.h>

#include "cryptohome/credential_verifier.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {

class ScryptVerifier final : public SyncCredentialVerifier {
 public:
  // Attempt to construct a credential verifier with the given passkey. Will
  // return null on failure.
  static std::unique_ptr<ScryptVerifier> Create(
      std::string auth_factor_label, const brillo::SecureBlob& passkey);

  ScryptVerifier(const ScryptVerifier&) = delete;
  ScryptVerifier& operator=(const ScryptVerifier&) = delete;

 private:
  ScryptVerifier(std::string auth_factor_label,
                 brillo::SecureBlob scrypt_salt,
                 brillo::SecureBlob verifier);

  CryptohomeStatus VerifySync(const AuthInput& secret) const override;

  const brillo::SecureBlob scrypt_salt_;
  const brillo::SecureBlob verifier_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_VERIFIERS_SCRYPT_H_
