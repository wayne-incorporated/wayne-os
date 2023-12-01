// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_CHALLENGE_CREDENTIAL_AUTH_BLOCK_H_
#define CRYPTOHOME_AUTH_BLOCKS_CHALLENGE_CREDENTIAL_AUTH_BLOCK_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/crypto.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_challenge_service.h"
#include "cryptohome/key_challenge_service_factory.h"
#include "cryptohome/username.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {

// The auth block definition for challenge credential.
// Note: Create/Derive cannot be called twice after we instantiate this auth
// block.
class ChallengeCredentialAuthBlock : public AuthBlock {
 public:
  // Implement the GenericAuthBlock concept.
  static constexpr auto kType = AuthBlockType::kChallengeCredential;
  using StateType = ChallengeCredentialAuthBlockState;
  static CryptoStatus IsSupported(Crypto& crypto);
  static std::unique_ptr<AuthBlock> New(
      const AuthInput& auth_input,
      AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
      KeyChallengeServiceFactory* key_challenge_service_factory);

  ChallengeCredentialAuthBlock(
      ChallengeCredentialsHelper* challenge_credentials_helper,
      std::unique_ptr<KeyChallengeService> key_challenge_service,
      const Username& account_id);

  ChallengeCredentialAuthBlock(const ChallengeCredentialAuthBlock&) = delete;
  ChallengeCredentialAuthBlock& operator=(const ChallengeCredentialAuthBlock&) =
      delete;

  // This creates the KeyBlobs & AuthBlockState  from the key challenge service.
  void Create(const AuthInput& user_input, CreateCallback callback) override;

  // This derives the KeyBlobs from the key challenge service.
  void Derive(const AuthInput& user_input,
              const AuthBlockState& state,
              DeriveCallback callback) override;

 private:
  // This continues the creating process after generated the new high entropy
  // secret from the key challenge service.
  void CreateContinue(
      CreateCallback callback,
      CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
          result);

  // This continues the creating process after Scrypt::Create.
  void CreateContinueAfterScrypt(
      CreateCallback callback,
      std::unique_ptr<structure::SignatureChallengeInfo>
          signature_challenge_info,
      CryptohomeStatus error,
      std::unique_ptr<KeyBlobs> key_blobs,
      std::unique_ptr<AuthBlockState> auth_block_state);

  // This continues the deriving process after decrypted the high entropy secret
  // from the key challenge service.
  void DeriveContinue(
      DeriveCallback callback,
      const AuthBlockState& scrypt_state,
      CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
          result);

  ChallengeCredentialsHelper* const challenge_credentials_helper_;
  std::unique_ptr<KeyChallengeService> key_challenge_service_;
  const Username account_id_;

  base::WeakPtrFactory<ChallengeCredentialAuthBlock> weak_factory_{this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_CHALLENGE_CREDENTIAL_AUTH_BLOCK_H_
