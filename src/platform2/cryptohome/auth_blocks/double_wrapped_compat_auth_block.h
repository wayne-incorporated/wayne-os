// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_DOUBLE_WRAPPED_COMPAT_AUTH_BLOCK_H_
#define CRYPTOHOME_AUTH_BLOCKS_DOUBLE_WRAPPED_COMPAT_AUTH_BLOCK_H_

#include "cryptohome/auth_blocks/auth_block.h"

#include <memory>

#include <base/gtest_prod_util.h>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"
#include "cryptohome/crypto.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "libhwsec/frontend/cryptohome/frontend.h"

namespace cryptohome {

class CryptohomeKeysManager;

class DoubleWrappedCompatAuthBlock : public AuthBlock {
 public:
  // Implement the GenericAuthBlock concept.
  static constexpr auto kType = AuthBlockType::kDoubleWrappedCompat;
  using StateType = DoubleWrappedCompatAuthBlockState;
  static CryptoStatus IsSupported(Crypto& crypto);
  static std::unique_ptr<AuthBlock> New(
      const hwsec::CryptohomeFrontend& hwsec,
      CryptohomeKeysManager& cryptohome_keys_manager);

  DoubleWrappedCompatAuthBlock(const hwsec::CryptohomeFrontend* hwsec,
                               CryptohomeKeysManager* cryptohome_keys_manager);

  DoubleWrappedCompatAuthBlock(const DoubleWrappedCompatAuthBlock&) = delete;
  DoubleWrappedCompatAuthBlock& operator=(const DoubleWrappedCompatAuthBlock&) =
      delete;

  // This auth block represents legacy keysets left in an inconsistent state, so
  // calling Create() here is FATAL.
  void Create(const AuthInput& user_input, CreateCallback callback) override;

  // First tries to derive the keys with scrypt, and falls back to the TPM.
  void Derive(const AuthInput& user_input,
              const AuthBlockState& state,
              DeriveCallback callback) override;

 private:
  void CreateDeriveAfterScrypt(DeriveCallback callback,
                               const AuthInput& user_input,
                               const AuthBlockState& state,
                               CryptohomeStatus error,
                               std::unique_ptr<KeyBlobs> key_blobs,
                               std::optional<SuggestedAction> suggested_action);

  void CreateDeriveAfterTpm(DeriveCallback callback,
                            CryptohomeStatus error,
                            std::unique_ptr<KeyBlobs> key_blobs,
                            std::optional<SuggestedAction> suggested_action);
  ScryptAuthBlock scrypt_auth_block_;
  TpmNotBoundToPcrAuthBlock tpm_auth_block_;
  base::WeakPtrFactory<DoubleWrappedCompatAuthBlock> weak_factory_{this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_DOUBLE_WRAPPED_COMPAT_AUTH_BLOCK_H_
