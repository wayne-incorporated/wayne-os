// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_TPM_ECC_AUTH_BLOCK_H_
#define CRYPTOHOME_AUTH_BLOCKS_TPM_ECC_AUTH_BLOCK_H_

#include "cryptohome/auth_blocks/auth_block.h"

#include <memory>
#include <string>

#include <base/gtest_prod_util.h>
#include <base/threading/thread.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/structures/key.h>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"
#include "cryptohome/crypto.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/vault_keyset.pb.h"

namespace cryptohome {

class TpmEccAuthBlock : public AuthBlock {
 public:
  // Implement the GenericAuthBlock concept.
  static constexpr auto kType = AuthBlockType::kTpmEcc;
  using StateType = TpmEccAuthBlockState;
  static CryptoStatus IsSupported(Crypto& crypto);
  static std::unique_ptr<AuthBlock> New(
      const hwsec::CryptohomeFrontend& hwsec,
      CryptohomeKeysManager& cryptohome_keys_manager);

  TpmEccAuthBlock(const hwsec::CryptohomeFrontend* hwsec,
                  CryptohomeKeysManager* cryptohome_keys_manager);

  TpmEccAuthBlock(const TpmEccAuthBlock&) = delete;
  TpmEccAuthBlock& operator=(const TpmEccAuthBlock&) = delete;

  void Create(const AuthInput& user_input, CreateCallback callback) override;

  void Derive(const AuthInput& auth_input,
              const AuthBlockState& state,
              DeriveCallback callback) override;

 private:
  // The create process may fail due to the scalar of EC_POINT_mul out of range.
  // We should retry the process again when retry_limit is not zero.
  void TryCreate(const AuthInput& auth_input,
                 int retry_limit,
                 AuthBlock::CreateCallback callback);

  // Derive the VKK from the user input and auth state.
  CryptoStatus DeriveVkk(bool locked_to_single_user,
                         const brillo::SecureBlob& user_input,
                         const TpmEccAuthBlockState& auth_state,
                         brillo::SecureBlob* vkk);

  // Derive the HVKKM from sealed HVKKM, preload handle.
  CryptoStatus DeriveHvkkm(bool locked_to_single_user,
                           brillo::SecureBlob pass_blob,
                           const brillo::SecureBlob& sealed_hvkkm,
                           const std::optional<hwsec::ScopedKey>& preload_key,
                           uint32_t auth_value_rounds,
                           brillo::SecureBlob* vkk);

  const hwsec::CryptohomeFrontend* hwsec_;
  CryptohomeKeyLoader* cryptohome_key_loader_;
  TpmAuthBlockUtils utils_;

  // The thread for performing scrypt operations.
  std::unique_ptr<base::Thread> scrypt_thread_;
  // The task runner that belongs to the scrypt thread.
  scoped_refptr<base::SingleThreadTaskRunner> scrypt_task_runner_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_TPM_ECC_AUTH_BLOCK_H_
