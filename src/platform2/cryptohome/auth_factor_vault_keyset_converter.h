// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_VAULT_KEYSET_CONVERTER_H_
#define CRYPTOHOME_AUTH_FACTOR_VAULT_KEYSET_CONVERTER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/username.h"

namespace cryptohome {

// This class contains the methods to convert an AuthFactor data to a
// VaultKeyset data and to convert on-disk VaultKeysets data to AuthFactor data.
class AuthFactorVaultKeysetConverter {
 public:
  // Unowned pointer |keyset_management| should outlive the lifetime of the
  // AuthFactorVaultKeysetConverter object.
  explicit AuthFactorVaultKeysetConverter(KeysetManagement* keyset_management_);
  AuthFactorVaultKeysetConverter(const AuthFactorVaultKeysetConverter&) =
      delete;
  AuthFactorVaultKeysetConverter& operator=(
      const AuthFactorVaultKeysetConverter&) = delete;
  ~AuthFactorVaultKeysetConverter();

  // Generates and returns an AuthFactor type with the |key_data|
  std::unique_ptr<AuthFactor> VaultKeysetToAuthFactor(
      const ObfuscatedUsername& obfuscated_username, const std::string& label);

  // Returns all the existing VaultKeyset data on disk for migrated, backup and
  // regular VaultKeysets. Backup VaultKeysets and regular VaultKeysets
  // are returned mapped to their labels and converted into AuthFactor format.
  // For migrated VaultKeysets list of migrated VaultKeyset labels is returned
  // since it is a subset of backup VaultKeysets.
  user_data_auth::CryptohomeErrorCode VaultKeysetsToAuthFactorsAndKeyLabelData(
      const ObfuscatedUsername& obfuscated_username,
      std::vector<std::string>& migrated_labels,
      std::map<std::string, std::unique_ptr<AuthFactor>>&
          out_label_to_auth_factor,
      std::map<std::string, std::unique_ptr<AuthFactor>>&
          out_label_to_auth_factor_backup_vks);

  // Takes a label, which was sent from an AuthFactor API, find the VaultKeyset
  // identified with that label and returns its KeyData.
  user_data_auth::CryptohomeErrorCode PopulateKeyDataForVK(
      const ObfuscatedUsername& obfuscated_username,
      const std::string& auth_factor_label,
      KeyData& out_vk_key_data);

  // Generates a KeyData structure using the given auth factor
  // and auth input data.
  user_data_auth::CryptohomeErrorCode AuthFactorToKeyData(
      const std::string& auth_factor_label,
      const AuthFactorType& auth_factor_type,
      const AuthFactorMetadata& auth_factor_metadata,
      KeyData& out_vk_key_data);

 private:
  // Unowned pointer.
  KeysetManagement* const keyset_management_;
};

}  // namespace cryptohome
#endif  // CRYPTOHOME_AUTH_FACTOR_VAULT_KEYSET_CONVERTER_H_
