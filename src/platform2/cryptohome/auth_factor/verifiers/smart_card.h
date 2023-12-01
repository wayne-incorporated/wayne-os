// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_VERIFIERS_SMART_CARD_H_
#define CRYPTOHOME_AUTH_FACTOR_VERIFIERS_SMART_CARD_H_

#include <memory>
#include <string>
#include <utility>

#include <brillo/secure_blob.h>

#include "cryptohome/challenge_credentials/challenge_credentials_helper_impl.h"
#include "cryptohome/key_objects.h"

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/key_challenge_service_factory.h"
#include "cryptohome/key_challenge_service_factory_impl.h"

namespace cryptohome {

class SmartCardVerifier final : public AsyncCredentialVerifier {
 public:
  // Attempt to construct a credential verifier with the given passkey. Will
  // return null on failure.
  static std::unique_ptr<SmartCardVerifier> Create(
      std::string auth_factor_label,
      const brillo::Blob& public_key_blob,
      ChallengeCredentialsHelper* challenge_credentials_helper,
      KeyChallengeServiceFactory* key_challenge_service_factory);

  SmartCardVerifier(const SmartCardVerifier&) = delete;
  SmartCardVerifier& operator=(const SmartCardVerifier&) = delete;

  // This verifies auth_input against a key_challenge service.
  void VerifyAsync(const AuthInput& auth_input,
                   StatusCallback callback) const override;

 private:
  SmartCardVerifier(std::string auth_factor_label,
                    const brillo::Blob& public_key_blob,
                    ChallengeCredentialsHelper* challenge_credentials_helper,
                    KeyChallengeServiceFactory* key_challenge_service_factory);

  // This continues the verification process after running a lightweight check
  // in the key challenge service.
  void OnVerifyContinue(StatusCallback callback, CryptoStatus status) const;

  // Challenge credential helper utility object. This object is required
  // for using a challenge response authblock.
  ChallengeCredentialsHelper* challenge_credentials_helper_ = nullptr;

  // Factory of key challenge service used to generate a key_challenge_service
  // for Challenge Credentials. KeyChallengeService is tasked with contacting
  // the challenge response D-Bus service that'll provide the response once
  // we send the challenge.
  KeyChallengeServiceFactory* key_challenge_service_factory_ = nullptr;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_VERIFIERS_SMART_CARD_H_
