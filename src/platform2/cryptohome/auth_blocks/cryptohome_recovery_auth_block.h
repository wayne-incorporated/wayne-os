// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_CRYPTOHOME_RECOVERY_AUTH_BLOCK_H_
#define CRYPTOHOME_AUTH_BLOCKS_CRYPTOHOME_RECOVERY_AUTH_BLOCK_H_

#include <memory>

#include <libhwsec/frontend/cryptohome/frontend.h>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/crypto.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {

// AuthBlock for Cryptohome Recovery flow. Secret is generated on the device and
// later derived by Cryptohome Recovery process using data stored on the device
// and by Recovery Mediator service.
class CryptohomeRecoveryAuthBlock : public AuthBlock {
 public:
  // Implement the GenericAuthBlock concept.
  static constexpr auto kType = AuthBlockType::kCryptohomeRecovery;
  using StateType = CryptohomeRecoveryAuthBlockState;
  static CryptoStatus IsSupported(Crypto& crypto);
  static std::unique_ptr<AuthBlock> New(
      Platform& platform,
      const hwsec::CryptohomeFrontend& hwsec,
      const hwsec::RecoveryCryptoFrontend& recovery_hwsec,
      LECredentialManager* le_manager);

  // the `tpm` pointer must outlive `this`
  explicit CryptohomeRecoveryAuthBlock(
      const hwsec::CryptohomeFrontend* hwsec,
      const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
      Platform* platform);
  explicit CryptohomeRecoveryAuthBlock(
      const hwsec::CryptohomeFrontend* hwsec,
      const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
      LECredentialManager* le_manager,
      Platform* platform);

  CryptohomeRecoveryAuthBlock(const CryptohomeRecoveryAuthBlock&) = delete;
  CryptohomeRecoveryAuthBlock& operator=(const CryptohomeRecoveryAuthBlock&) =
      delete;

  // `auth_input` object should have `salt` and
  // `cryptohome_recovery_auth_input.mediator_pub_key` fields set.
  void Create(const AuthInput& auth_input, CreateCallback callback) override;

  // `auth_input` object should have `salt`,
  // `cryptohome_recovery_auth_input.epoch_pub_key`,
  // `cryptohome_recovery_auth_input.ephemeral_pub_key` and
  // `cryptohome_recovery_auth_input.recovery_response` fields set.
  void Derive(const AuthInput& auth_input,
              const AuthBlockState& state,
              DeriveCallback callback) override;

  void PrepareForRemoval(const AuthBlockState& state,
                         StatusCallback callback) override;

 private:
  CryptoStatus PrepareForRemovalInternal(const AuthBlockState& state);

  const hwsec::CryptohomeFrontend* const hwsec_;
  const hwsec::RecoveryCryptoFrontend* const recovery_hwsec_;
  // Low Entropy credentials manager, needed for revocation support.
  LECredentialManager* const le_manager_;
  Platform* const platform_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_CRYPTOHOME_RECOVERY_AUTH_BLOCK_H_
