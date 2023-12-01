// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_GENERATE_NEW_OPERATION_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_GENERATE_NEW_OPERATION_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>

#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/challenge_credentials/challenge_credentials_operation.h"
#include "cryptohome/error/cryptohome_tpm_error.h"
#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/username.h"

namespace cryptohome {

class Credentials;
class KeyChallengeService;

// This operation generates new credentials for the given user and the
// referenced cryptographic key. This operation involves making challenge
// request(s) against the specified key.
//
// This class is not expected to be used directly by client code; instead,
// methods of ChallengeCredentialsHelper should be called.
class ChallengeCredentialsGenerateNewOperation final
    : public ChallengeCredentialsOperation {
 public:
  // If the operation succeeds, |passkey| can be used for decryption of the
  // user's vault keyset, and |signature_challenge_info| containing the data to
  // be stored in the auth block state.
  using CompletionCallback = base::OnceCallback<void(
      CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>)>;

  // |key_challenge_service| is a non-owned pointer which must outlive the
  // created instance.
  // |public_key_info| describes the challenge-response public key information.
  //
  // |obfuscated_username| is the binding username; the created credentials
  // will be protected in a way that decrypting them back is possible iff
  // the current user is correct.
  //
  // The result is reported via |completion_callback|.
  ChallengeCredentialsGenerateNewOperation(
      KeyChallengeService* key_challenge_service,
      const hwsec::CryptohomeFrontend* hwsec,
      const Username& account_id,
      const structure::ChallengePublicKeyInfo& public_key_info,
      const ObfuscatedUsername& obfuscated_username,
      CompletionCallback completion_callback);

  ~ChallengeCredentialsGenerateNewOperation() override;

  // ChallengeCredentialsOperation:
  void Start() override;
  void Abort(CryptoStatus status) override;

 private:
  // Starts the processing. Returns |false| on fatal error.
  CryptoStatus StartProcessing();

  // Generates a salt. Returns |false| on fatal error.
  CryptoStatus GenerateSalt();

  // Makes a challenge request against the salt. Returns |false| on fatal error.
  CryptoStatus StartGeneratingSaltSignature();

  // Creates a TPM-protected signature-sealed secret.
  CryptoStatus CreateTpmProtectedSecret();

  // Called when signature for the salt is received.
  void OnSaltChallengeResponse(
      CryptoStatusOr<std::unique_ptr<brillo::Blob>> salt_signature);

  // Generates the result if all necessary pieces are computed.
  void ProceedIfComputationsDone();

  // Constructs the SignatureChallengeInfo that will be persisted as
  // part of the auth block state.
  structure::SignatureChallengeInfo ConstructKeysetSignatureChallengeInfo()
      const;

  const Username account_id_;
  const structure::ChallengePublicKeyInfo public_key_info_;
  const ObfuscatedUsername obfuscated_username_;
  CompletionCallback completion_callback_;
  const hwsec::CryptohomeFrontend* const hwsec_;
  brillo::Blob salt_;
  structure::ChallengeSignatureAlgorithm salt_signature_algorithm_ =
      structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1;
  std::unique_ptr<brillo::Blob> salt_signature_;
  std::unique_ptr<brillo::SecureBlob> tpm_protected_secret_value_;
  hwsec::SignatureSealedData tpm_sealed_secret_data_;
  base::WeakPtrFactory<ChallengeCredentialsGenerateNewOperation>
      weak_ptr_factory_{this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_GENERATE_NEW_OPERATION_H_
