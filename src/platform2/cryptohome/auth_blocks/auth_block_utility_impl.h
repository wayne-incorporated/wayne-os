// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_UTILITY_IMPL_H_
#define CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_UTILITY_IMPL_H_

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/auth_block_utility.h"
#include "cryptohome/auth_blocks/biometrics_auth_block_service.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/crypto.h"
#include "cryptohome/features.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_challenge_service.h"
#include "cryptohome/key_challenge_service_factory.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/platform.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {

// Implementation of the AuthBlockUtility interface to create KeyBlobs with
// AuthBlocks using user credentials and derive KeyBlobs with AuthBlocks using
// credentials and stored AuthBlock state.
class AuthBlockUtilityImpl final : public AuthBlockUtility {
 public:
  // |keyset_management|, |crypto| and |platform| are non-owned objects. Caller
  // must ensure that these objects are valid for the lifetime of
  // AuthBlockUtilityImpl.
  AuthBlockUtilityImpl(
      KeysetManagement* keyset_management,
      Crypto* crypto,
      Platform* platform,
      AsyncInitFeatures* features,
      AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
      KeyChallengeServiceFactory* key_challenge_service_factory,
      AsyncInitPtr<BiometricsAuthBlockService> bio_service);

  AuthBlockUtilityImpl(const AuthBlockUtilityImpl&) = delete;
  AuthBlockUtilityImpl& operator=(const AuthBlockUtilityImpl&) = delete;

  bool GetLockedToSingleUser() const override;

  void CreateKeyBlobsWithAuthBlock(
      AuthBlockType auth_block_type,
      const AuthInput& auth_input,
      AuthBlock::CreateCallback create_callback) override;

  void DeriveKeyBlobsWithAuthBlock(
      AuthBlockType auth_block_type,
      const AuthInput& auth_input,
      const AuthBlockState& auth_state,
      AuthBlock::DeriveCallback derive_callback) override;

  void SelectAuthFactorWithAuthBlock(
      AuthBlockType auth_block_type,
      const AuthInput& auth_input,
      std::vector<AuthFactor> auth_factors,
      AuthBlock::SelectFactorCallback select_callback) override;

  CryptoStatusOr<AuthBlockType> SelectAuthBlockTypeForCreation(
      base::span<const AuthBlockType> block_types) const override;

  std::optional<AuthBlockType> GetAuthBlockTypeFromState(
      const AuthBlockState& state) const override;

  void PrepareAuthBlockForRemoval(const AuthBlockState& auth_block_state,
                                  CryptohomeStatusCallback callback) override;

  CryptoStatus GenerateRecoveryRequest(
      const ObfuscatedUsername& obfuscated_username,
      const cryptorecovery::RequestMetadata& request_metadata,
      const brillo::Blob& epoch_response,
      const CryptohomeRecoveryAuthBlockState& state,
      const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
      brillo::SecureBlob* out_recovery_request,
      brillo::SecureBlob* out_ephemeral_pub_key) const override;

  // Factory function to construct an auth block of the given type.
  CryptoStatusOr<std::unique_ptr<AuthBlock>> GetAuthBlockWithType(
      AuthBlockType auth_block_type, const AuthInput& auth_input);

 private:
  // Determine if a given type of auth block is supported.
  CryptoStatus IsAuthBlockSupported(AuthBlockType auth_block_type) const;

  // Non-owned object used for the keyset management operations. Must be alive
  // for the entire lifecycle of the class.
  KeysetManagement* const keyset_management_;

  // Non-owned crypto object for performing cryptographic operations. Must be
  // alive for the entire lifecycle of the class.
  Crypto* const crypto_;

  // Non-owned platform object used in this class. Must be alive for the entire
  // lifecycle of the class.
  Platform* const platform_;

  // Non-owned features object used in this class. Must be alive for the entire
  // lifetime of the class.
  AsyncInitFeatures* const features_;

  // Challenge credential helper utility object. This object is required
  // for using a challenge response authblock.
  AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper_;

  // Factory of key challenge service used to generate a key_challenge_service
  // for Challenge Credentials. KeyChallengeService is tasked with contacting
  // the challenge response D-Bus service that'll provide the response once
  // we send the challenge.
  KeyChallengeServiceFactory* key_challenge_service_factory_;

  // Biometrics service, used by operations that need to interact with biod.
  // TODO(b/276453357): Replace with BiometricsAuthBlockService* once that
  // object is guaranteed to always be available.
  AsyncInitPtr<BiometricsAuthBlockService> bio_service_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_UTILITY_IMPL_H_
