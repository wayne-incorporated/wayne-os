// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_OPERATION_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_OPERATION_H_

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <base/threading/thread_checker.h>
#include <brillo/secure_blob.h>

#include "cryptohome/error/cryptohome_tpm_error.h"
#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/username.h"

namespace cryptohome {

class KeyChallengeService;

// Base class for implementing specific operations that are exposed by
// ChallengeCredentialsHelper.
//
// Methods of this class and its subclasses must be called on the same thread.
class ChallengeCredentialsOperation {
 public:
  // This callback reports results of a MakeSignatureChallenge() call.
  //
  // If the challenge succeeded, then |signature| will contain the signature of
  // the challenge. Otherwise, it will be null.
  using KeySignatureChallengeCallback = base::OnceCallback<void(
      CryptoStatusOr<std::unique_ptr<brillo::Blob>> signature)>;

  virtual ~ChallengeCredentialsOperation();

  // Should begin the operation after this method is called.
  //
  // The implementation should guarantee that the completion callback shouldn't
  // be called before this method is called.
  virtual void Start() = 0;

  // Should complete the operation with an error result.
  //
  // If the completion already happened, should do nothing.
  virtual void Abort(CryptoStatus status) = 0;

 protected:
  static brillo::SecureBlob ConstructPasskey(
      const brillo::SecureBlob& tpm_protected_secret_value,
      const brillo::Blob& salt_signature);

  // |key_challenge_service| is a non-owned pointer which must outlive the
  // created instance.
  explicit ChallengeCredentialsOperation(
      KeyChallengeService* key_challenge_service);
  ChallengeCredentialsOperation(const ChallengeCredentialsOperation&) = delete;
  ChallengeCredentialsOperation& operator=(
      const ChallengeCredentialsOperation&) = delete;

  // Executes and resets the completion callback.
  // This method is intended to be used by subclasses, as the logic of
  // triggering completion callback should be the same for all of them.
  //
  // NOTE: |this| may become destroyed after calling this method.
  template <typename CompletionCallback, typename... Args>
  static void Complete(CompletionCallback* completion_callback,
                       Args&&... args) {
    if (completion_callback->is_null())
      return;
    // Move the callback into a temporary variable *before* running it, as the
    // value passed via |completion_callback| may become destroyed during the
    // callback execution.
    CompletionCallback callback_copy;
    std::swap(*completion_callback, callback_copy);
    std::move(callback_copy).Run(std::forward<Args>(args)...);
  }

  template <typename CompletionCallback>
  static void CompleteWithError(CompletionCallback* completion_callback,
                                CryptoStatus status
                                [[clang::param_typestate(unconsumed)]]) {
    if (completion_callback->is_null())
      return;
    // Move the callback into a temporary variable *before* running it, as the
    // value passed via |completion_callback| may become destroyed during the
    // callback execution.
    CompletionCallback callback_copy;
    std::swap(*completion_callback, callback_copy);
    std::move(callback_copy).Run(std::move(status));
  }

  // Starts a signature challenge request. In real use cases, this will make an
  // IPC request to the service that talks to the cryptographic token with the
  // challenged key.
  void MakeKeySignatureChallenge(
      const Username& account_id,
      const brillo::Blob& public_key_spki_der,
      const brillo::Blob& data_to_sign,
      structure::ChallengeSignatureAlgorithm signature_algorithm,
      KeySignatureChallengeCallback response_callback);

  base::ThreadChecker thread_checker_;

 private:
  // Not owned.
  KeyChallengeService* const key_challenge_service_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_OPERATION_H_
