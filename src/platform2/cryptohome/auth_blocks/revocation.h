// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_REVOCATION_H_
#define CRYPTOHOME_AUTH_BLOCKS_REVOCATION_H_

#include <libhwsec/frontend/cryptohome/frontend.h>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/le_credential_manager.h"

namespace cryptohome {
namespace revocation {

bool IsRevocationSupported(const hwsec::CryptohomeFrontend* hwsec);

// Derives a new key from `in_out_key_blobs.vkk_key` and saves it back to
// `in_out_key_blobs.vkk_key`. Saves information that is required for key
// derivation to `in_out_revocation_state`.
CryptoStatus Create(LECredentialManager* le_manager,
                    RevocationState* in_out_revocation_state,
                    KeyBlobs* in_out_key_blobs);

// Derives a new key from `in_out_key_blobs.vkk_key` using information from
// `revocation_state` and saves it back to `in_out_key_blobs.vkk_key`.
CryptoStatus Derive(LECredentialManager* le_manager,
                    const RevocationState& revocation_state,
                    KeyBlobs* in_out_key_blobs);

// Removes data required to derive a key from provided `revocation_state`.
// `auth_block_type` is used for metrics.
CryptoStatus Revoke(AuthBlockType auth_block_type,
                    LECredentialManager* le_manager,
                    const RevocationState& revocation_state);

}  // namespace revocation
}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_REVOCATION_H_
