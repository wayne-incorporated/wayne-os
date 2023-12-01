// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CREATE_VAULT_KEYSET_RPC_IMPL_H_
#define CRYPTOHOME_CREATE_VAULT_KEYSET_RPC_IMPL_H_

#include <memory>
#include <string>

#include "cryptohome/auth_blocks/auth_block_utility.h"
#include "cryptohome/auth_factor/types/manager.h"
#include "cryptohome/auth_session_manager.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {
class CreateVaultKeysetRpcImpl {
 public:
  CreateVaultKeysetRpcImpl(KeysetManagement* keyset_management,
                           AuthBlockUtility* auth_block_utility,
                           AuthFactorDriverManager* auth_factor_driver_manager,
                           InUseAuthSession auth_session);

  CreateVaultKeysetRpcImpl(const CreateVaultKeysetRpcImpl&) = delete;
  CreateVaultKeysetRpcImpl& operator=(const CreateVaultKeysetRpcImpl&) = delete;

  void CreateVaultKeyset(
      const user_data_auth::CreateVaultKeysetRequest& request,
      StatusCallback on_done);

 private:
  bool ClearKeyDataFromInitialKeyset(bool disable_key_data);
  void CreateAndPersistVaultKeyset(const KeyData& key_data,
                                   const bool disable_key_data,
                                   AuthInput auth_input,
                                   StatusCallback on_done,
                                   CryptohomeStatus callback_error,
                                   std::unique_ptr<KeyBlobs> key_blobs,
                                   std::unique_ptr<AuthBlockState> auth_state);

  CryptohomeStatus AddVaultKeyset(const std::string& key_label,
                                  const KeyData& key_data,
                                  bool is_initial_keyset,
                                  VaultKeysetIntent vk_backup_intent,
                                  std::unique_ptr<KeyBlobs> key_blobs,
                                  std::unique_ptr<AuthBlockState> auth_state);

  KeysetManagement* const keyset_management_;
  AuthBlockUtility* const auth_block_utility_;
  AuthFactorDriverManager* const auth_factor_driver_manager_;
  InUseAuthSession auth_session_;

  // Used to decrypt/ encrypt & store credentials.
  std::unique_ptr<VaultKeyset> initial_vault_keyset_;

  // Should be the last member.
  base::WeakPtrFactory<CreateVaultKeysetRpcImpl> weak_factory_{this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CREATE_VAULT_KEYSET_RPC_IMPL_H_
