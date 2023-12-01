// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_DECRYPT_OPERATION_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_DECRYPT_OPERATION_H_

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/secure_blob.h>
#include <libhwsec/error/tpm_error.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>

#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/challenge_credentials/challenge_credentials_operation.h"
#include "cryptohome/error/cryptohome_tpm_error.h"
#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/username.h"

namespace cryptohome {

class Credentials;
class KeyChallengeService;

// This operation decrypts the credentials for the given user and the referenced
// cryptographic key. This operation involves making challenge request(s)
// against the specified key.
//
// This class is not expected to be used directly by client code; instead,
// methods of ChallengeCredentialsHelper should be called.
class ChallengeCredentialsDecryptOperation final
    : public ChallengeCredentialsOperation {
 public:
  // If the operation succeeds, |passkey| can be used for decryption of the
  // user's vault keyset.
  using CompletionCallback = base::OnceCallback<void(
      CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>)>;

  // |key_challenge_service| is a non-owned pointer which must outlive the
  // created instance.
  // |public_key_info| describes the challenge-response public key information.
  // |keyset_challenge_info| contains the encrypted representation of secrets.
  // The result is reported via |completion_callback|.
  ChallengeCredentialsDecryptOperation(
      KeyChallengeService* key_challenge_service,
      const hwsec::CryptohomeFrontend* hwsec,
      const Username& account_id,
      const structure::ChallengePublicKeyInfo& public_key_info,
      const structure::SignatureChallengeInfo& keyset_challenge_info,
      CompletionCallback completion_callback);

  ~ChallengeCredentialsDecryptOperation() override;

  // ChallengeCredentialsOperation:
  void Start() override;
  void Abort(CryptoStatus status) override;

 private:
  // Starts the processing.
  hwsec_foundation::status::StatusChain<
      cryptohome::error::CryptohomeCryptoError>
  StartProcessing();

  // Makes a challenge request with the salt.
  hwsec_foundation::status::StatusChain<
      cryptohome::error::CryptohomeCryptoError>
  StartProcessingSalt();

  // Begins unsealing the secret, and makes a challenge request for unsealing
  // it.
  hwsec_foundation::status::StatusChain<
      cryptohome::error::CryptohomeCryptoError>
  StartProcessingSealedSecret();

  // Called when signature for the salt is received.
  void OnSaltChallengeResponse(
      CryptoStatusOr<std::unique_ptr<brillo::Blob>> salt_signature);

  // Called when signature for the unsealing challenge is received.
  void OnUnsealingChallengeResponse(
      CryptoStatusOr<std::unique_ptr<brillo::Blob>> challenge_signature);

  // Generates the result if all necessary challenges are completed.
  void ProceedIfChallengesDone();

  // Completes with returning the specified results.
  void Resolve(
      CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>);

  const Username account_id_;
  const structure::ChallengePublicKeyInfo public_key_info_;
  const structure::SignatureChallengeInfo keyset_challenge_info_;
  std::unique_ptr<brillo::Blob> salt_signature_;
  CompletionCallback completion_callback_;
  const hwsec::CryptohomeFrontend* const hwsec_;
  std::optional<hwsec::CryptohomeFrontend::ChallengeID> challenge_id_;
  std::unique_ptr<brillo::SecureBlob> unsealed_secret_;
  base::WeakPtrFactory<ChallengeCredentialsDecryptOperation> weak_ptr_factory_{
      this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_DECRYPT_OPERATION_H_
