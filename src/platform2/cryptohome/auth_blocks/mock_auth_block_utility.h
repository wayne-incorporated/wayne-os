// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_MOCK_AUTH_BLOCK_UTILITY_H_
#define CRYPTOHOME_AUTH_BLOCKS_MOCK_AUTH_BLOCK_UTILITY_H_

#include "cryptohome/auth_blocks/auth_block_utility.h"

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/username.h"

namespace cryptohome {

class MockAuthBlockUtility : public AuthBlockUtility {
 public:
  MockAuthBlockUtility();

  MOCK_METHOD(bool, GetLockedToSingleUser, (), (const, override));
  MOCK_METHOD(void,
              CreateKeyBlobsWithAuthBlock,
              (AuthBlockType auth_block_type,
               const AuthInput& auth_input,
               AuthBlock::CreateCallback create_callback),
              (override));
  MOCK_METHOD(void,
              DeriveKeyBlobsWithAuthBlock,
              (AuthBlockType auth_block_type,
               const AuthInput& auth_input,
               const AuthBlockState& auth_state,
               AuthBlock::DeriveCallback derive_callback),
              (override));
  MOCK_METHOD(void,
              SelectAuthFactorWithAuthBlock,
              (AuthBlockType auth_block_type,
               const AuthInput& auth_input,
               std::vector<AuthFactor> auth_factors,
               AuthBlock::SelectFactorCallback select_callback),
              (override));
  MOCK_METHOD(CryptoStatusOr<AuthBlockType>,
              SelectAuthBlockTypeForCreation,
              (base::span<const AuthBlockType>),
              (const, override));
  MOCK_METHOD(std::optional<AuthBlockType>,
              GetAuthBlockTypeFromState,
              (const AuthBlockState& auth_state),
              (const, override));
  MOCK_METHOD(void,
              PrepareAuthBlockForRemoval,
              (const AuthBlockState& auth_block_state, StatusCallback callback),
              (override));
  MOCK_METHOD(CryptoStatus,
              GenerateRecoveryRequest,
              (const ObfuscatedUsername& obfuscated_username,
               const cryptorecovery::RequestMetadata& request_metadata,
               const brillo::Blob& epoch_response,
               const CryptohomeRecoveryAuthBlockState& state,
               const hwsec::RecoveryCryptoFrontend* recovery_hwsec,
               brillo::SecureBlob* out_recovery_request,
               brillo::SecureBlob* out_ephemeral_pub_key),
              (const, override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_MOCK_AUTH_BLOCK_UTILITY_H_
