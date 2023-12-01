// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_VERIFY_KEY_OPERATION_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_VERIFY_KEY_OPERATION_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>

#include "cryptohome/challenge_credentials/challenge_credentials_operation.h"
#include "cryptohome/username.h"

namespace cryptohome {

class KeyChallengeService;

// This operation verifies that the specified cryptographic key is available and
// can be used for authentication. This operation involves making challenge
// request(s) against the key.
//
// This class is not expected to be used directly by client code; instead,
// methods of ChallengeCredentialsHelper should be called.
class ChallengeCredentialsVerifyKeyOperation final
    : public ChallengeCredentialsOperation {
 public:
  // Returns whether the authentication using the specified key succeeded.
  // An OK status is returned for successful verification. A status with
  // kIncorrectAuth is returned if it failed and the user is at fault.
  // Otherwise, other actions are returned.
  using CompletionCallback = base::OnceCallback<void(CryptoStatus status)>;

  // |key_challenge_service| is a non-owned pointer which must outlive the
  // created instance.
  // |public_key_info| describes the challenge-response public key information.
  //
  // The result is reported via |completion_callback|.
  ChallengeCredentialsVerifyKeyOperation(
      KeyChallengeService* key_challenge_service,
      const hwsec::CryptohomeFrontend* hwsec,
      const Username& account_id,
      const structure::ChallengePublicKeyInfo& public_key_info,
      CompletionCallback completion_callback);

  ~ChallengeCredentialsVerifyKeyOperation() override;

  // ChallengeCredentialsOperation:
  void Start() override;
  void Abort(CryptoStatus status) override;

 private:
  void OnChallengeResponse(
      const brillo::Blob& public_key_spki_der,
      structure::ChallengeSignatureAlgorithm challenge_algorithm,
      const brillo::Blob& challenge,
      CryptoStatusOr<std::unique_ptr<brillo::Blob>> challenge_signature);

  const hwsec::CryptohomeFrontend* const hwsec_;
  const Username account_id_;
  const structure::ChallengePublicKeyInfo public_key_info_;
  CompletionCallback completion_callback_;
  base::WeakPtrFactory<ChallengeCredentialsVerifyKeyOperation>
      weak_ptr_factory_{this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_VERIFY_KEY_OPERATION_H_
