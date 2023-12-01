// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_HELPER_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_HELPER_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <brillo/secure_blob.h>

#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/key_challenge_service.h"
#include "cryptohome/username.h"

namespace cryptohome {

// This class provides generation of credentials for challenge-protected vault
// keysets, and verification of key validity for such keysets.
//
// It's expected that the consumer code instantiates a single instance during
// the whole daemon lifetime. This allows to keep the resource usage
// constrained, e.g., to have a limited number of active TPM sessions.
//
// NOTE: This object supports only one operation (GenerateNew() / Decrypt() /
// VerifyKey()) at a time. Starting a new operation before the previous one
// completes will lead to cancellation of the previous operation (i.e., the
// old operation will complete with a failure).
//
// This class must be used on a single thread only.
class ChallengeCredentialsHelper {
 public:
  // A simple storage struct for storing the results of Decrypt() or
  // GenerateNew(). For Decrypt(), the signature_challenge_info field is always
  // nullptr.
  class GenerateNewOrDecryptResult {
   public:
    GenerateNewOrDecryptResult(
        std::unique_ptr<structure::SignatureChallengeInfo>
            signature_challenge_info,
        std::unique_ptr<brillo::SecureBlob> passkey)
        : info_(std::move(signature_challenge_info)),
          passkey_(std::move(passkey)) {}

    // Getters
    std::unique_ptr<structure::SignatureChallengeInfo> info() {
      return std::move(info_);
    }
    std::unique_ptr<brillo::SecureBlob> passkey() {
      return std::move(passkey_);
    }

    // Const getters
    const structure::SignatureChallengeInfo* info() const {
      return info_.get();
    }
    const brillo::SecureBlob* passkey() const { return passkey_.get(); }

   private:
    std::unique_ptr<structure::SignatureChallengeInfo> info_;
    std::unique_ptr<brillo::SecureBlob> passkey_;
  };

  // This callback reports result of a GenerateNew() call.
  //
  // If the operation succeeds, the result struct will contain the |passkey|,
  // which can be used for decryption of the user's vault keyset, and
  // |signature_challenge_info|, which contains the data to be stored in the
  // auth block state. If the operation fails, the argument will be the
  // CryptoStatus on the details of the failure.
  using GenerateNewCallback =
      base::OnceCallback<void(CryptoStatusOr<GenerateNewOrDecryptResult>)>;

  // This callback reports result of a Decrypt() call.
  //
  // If the operation succeeds, result struct will contain the passkey, which
  // can be used for decryption of the user's vault keyset. The
  // signature_challenge_info field is always nullptr. If the operation fails,
  // the argument will be the CryptoStatus on details of the failure.
  using DecryptCallback =
      base::OnceCallback<void(CryptoStatusOr<GenerateNewOrDecryptResult>)>;

  // This callback reports result of a VerifyKey() call.
  //
  // The |is_key_valid| argument will be true iff the operation succeeds and
  // the provided key is valid for decryption of the given vault keyset.
  // An OK status is returned for successful verification. A status with
  // kIncorrectAuth is returned if it failed and the user is at fault.
  // Otherwise, other actions are returned.
  using VerifyKeyCallback = base::OnceCallback<void(CryptoStatus)>;

  // The maximum number of attempts that will be made for a single operation
  // when it fails with a transient error.
  static constexpr int kRetryAttemptCount = 3;

  ChallengeCredentialsHelper() = default;
  ChallengeCredentialsHelper(const ChallengeCredentialsHelper&) = delete;
  ChallengeCredentialsHelper& operator=(const ChallengeCredentialsHelper&) =
      delete;
  virtual ~ChallengeCredentialsHelper() = default;

  // Generates and returns fresh random-based credentials for the given user
  // and the referenced key, and also returns the encrypted
  // (challenge-protected) representation of the created secrets that should
  // be stored in the created vault keyset. This operation may involve making
  // challenge request(s) against the specified key.
  //
  // |obfuscated_username| is the obfuscated username; the created credentials
  // will be protected in a way that decrypting them back is possible iff the
  // current user is satisfied.
  //
  // The result is reported via |callback|.
  virtual void GenerateNew(
      const Username& account_id,
      const structure::ChallengePublicKeyInfo& public_key_info,
      const ObfuscatedUsername& obfuscated_username,
      std::unique_ptr<KeyChallengeService> key_challenge_service,
      GenerateNewCallback callback) = 0;

  // Builds credentials for the given user, based on the encrypted
  // (challenge-protected) representation of the previously created secrets. The
  // referred cryptographic key should be the same as the one used for the
  // secrets generation via GenerateNew(); although a difference in the key's
  // supported algorithms may be tolerated in some cases. This operation
  // involves making challenge request(s) against the key.
  //
  // |keyset_challenge_info| is the encrypted representation of secrets as
  // created via GenerateNew().
  // The result is reported via |callback|.
  virtual void Decrypt(
      const Username& account_id,
      const structure::ChallengePublicKeyInfo& public_key_info,
      const structure::SignatureChallengeInfo& keyset_challenge_info,
      std::unique_ptr<KeyChallengeService> key_challenge_service,
      DecryptCallback callback) = 0;

  // Verifies that the specified cryptographic key is available and can be used
  // for authentication. This operation involves making challenge request(s)
  // against the key. This method is intended as a lightweight analog of
  // Decrypt() for cases where the actual credentials aren't needed.
  //
  // The result is reported via |callback|.
  virtual void VerifyKey(
      const Username& account_id,
      const structure::ChallengePublicKeyInfo& public_key_info,
      std::unique_ptr<KeyChallengeService> key_challenge_service,
      VerifyKeyCallback callback) = 0;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_HELPER_H_
