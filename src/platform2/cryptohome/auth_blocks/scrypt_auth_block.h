// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_SCRYPT_AUTH_BLOCK_H_
#define CRYPTOHOME_AUTH_BLOCKS_SCRYPT_AUTH_BLOCK_H_

#include <memory>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"

namespace cryptohome {

// This auth block would generate the standard vkk_key that's
// similar to the other standard auth block.
class ScryptAuthBlock : public AuthBlock {
 public:
  // Implement the GenericAuthBlock concept.
  static constexpr auto kType = AuthBlockType::kScrypt;
  using StateType = ScryptAuthBlockState;
  static CryptoStatus IsSupported(Crypto& crypto);
  static std::unique_ptr<AuthBlock> New();

  ScryptAuthBlock();

  ScryptAuthBlock(const ScryptAuthBlock&) = delete;
  ScryptAuthBlock& operator=(const ScryptAuthBlock&) = delete;

  // Derives a high entropy secret from the user's password with scrypt.
  // Returns a key for each field that must be wrapped by scrypt, such as the
  // wrapped_chaps_key, etc.
  void Create(const AuthInput& user_input, CreateCallback callback) override;

  // This uses Scrypt to derive high entropy keys from the user's password.
  void Derive(const AuthInput& auth_input,
              const AuthBlockState& state,
              DeriveCallback callback) override;

 protected:
  explicit ScryptAuthBlock(DerivationType);
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_SCRYPT_AUTH_BLOCK_H_
