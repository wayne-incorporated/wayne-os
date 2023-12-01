// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor_vault_keyset_converter.h"

#include <base/check.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/key.pb.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/auth_block_utils.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_label.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/vault_keyset.h"
#include "cryptohome/vault_keyset.pb.h"

namespace cryptohome {

namespace {

// Prefix for the smartphone (easyunlock, smartunlock) VaultKeyset label.
constexpr char kEasyUnlockLabelPrefix[] = "easy-unlock-";

// Construct the AuthFactor metadata based on AuthFactor type.
bool GetAuthFactorMetadataWithType(const AuthFactorType& type,
                                   AuthFactorMetadata& metadata,
                                   const KeyData& key_data) {
  switch (type) {
    case AuthFactorType::kPassword:
      metadata.metadata = auth_factor::PasswordMetadata();
      break;
    case AuthFactorType::kPin:
      metadata.metadata = auth_factor::PinMetadata();
      metadata.common.lockout_policy =
          auth_factor::LockoutPolicy::ATTEMPT_LIMITED;
      break;
    case AuthFactorType::kKiosk:
      metadata.metadata = auth_factor::KioskMetadata();
      break;
    case AuthFactorType::kSmartCard: {
      // Check for 0 or more than 1 challenge response key,
      // this is assumed to be only 1.
      if (key_data.challenge_response_key_size() != 1) {
        return false;
      }
      if (!key_data.challenge_response_key(0).has_public_key_spki_der()) {
        return false;
      }
      // For AuthFactorType::kSmartCard chose the first/only key by default.
      brillo::Blob public_key_blob = brillo::BlobFromString(
          key_data.challenge_response_key(0).public_key_spki_der());
      metadata.metadata = auth_factor::SmartCardMetadata{.public_key_spki_der =
                                                             public_key_blob};
      break;
    }
    default:
      return false;
  }
  return true;
}

// Returns the AuthFactor type mapped from the input VaultKeyset.
AuthFactorType VaultKeysetTypeToAuthFactorType(int32_t vk_flags,
                                               const KeyData& key_data) {
  // Kiosk is special, we need to identify it from key data and not flags.
  if (key_data.type() == KeyData::KEY_TYPE_KIOSK) {
    return AuthFactorType::kKiosk;
  }

  // Convert the VK flags to a block type and then that to a factor type.
  AuthBlockType auth_block_type;
  if (!FlagsToAuthBlockType(vk_flags, auth_block_type)) {
    LOG(ERROR) << "Failed to get the AuthBlock type for AuthFactor convertion.";
    return AuthFactorType::kUnspecified;
  }
  switch (auth_block_type) {
    case AuthBlockType::kDoubleWrappedCompat:
    case AuthBlockType::kTpmBoundToPcr:
    case AuthBlockType::kTpmNotBoundToPcr:
    case AuthBlockType::kTpmEcc:
    case AuthBlockType::kScrypt:
      return AuthFactorType::kPassword;
    case AuthBlockType::kPinWeaver:
      return AuthFactorType::kPin;
    case AuthBlockType::kChallengeCredential:
      return AuthFactorType::kSmartCard;
    case AuthBlockType::kCryptohomeRecovery:  // Never reported by a VK.
    case AuthBlockType::kFingerprint:         // Never reported by a VK.
      return AuthFactorType::kUnspecified;
  }
}

// Returns the AuthFactor object converted from the input VaultKeyset.
std::unique_ptr<AuthFactor> ConvertToAuthFactor(const VaultKeyset& vk) {
  AuthBlockState auth_block_state;
  if (!GetAuthBlockState(vk, auth_block_state /*out*/)) {
    return nullptr;
  }

  // If the VaultKeyset label is empty an artificial label legacy<index> is
  // returned.
  std::string label = vk.GetLabel();
  if (!IsValidAuthFactorLabel(label)) {
    return nullptr;
  }

  KeyData key_data = vk.GetKeyDataOrDefault();
  AuthFactorType auth_factor_type =
      VaultKeysetTypeToAuthFactorType(vk.GetFlags(), key_data);
  if (auth_factor_type == AuthFactorType::kUnspecified) {
    return nullptr;
  }

  AuthFactorMetadata metadata;
  if (!GetAuthFactorMetadataWithType(auth_factor_type, metadata, key_data)) {
    return nullptr;
  }

  return std::make_unique<AuthFactor>(auth_factor_type, label, metadata,
                                      auth_block_state);
}

}  // namespace

AuthFactorVaultKeysetConverter::AuthFactorVaultKeysetConverter(
    KeysetManagement* keyset_management)
    : keyset_management_(keyset_management) {
  DCHECK(keyset_management_);
}
AuthFactorVaultKeysetConverter::~AuthFactorVaultKeysetConverter() = default;

std::unique_ptr<AuthFactor>
AuthFactorVaultKeysetConverter::VaultKeysetToAuthFactor(
    const ObfuscatedUsername& obfuscated_username, const std::string& label) {
  std::unique_ptr<VaultKeyset> vk =
      keyset_management_->GetVaultKeyset(obfuscated_username, label);
  if (!vk) {
    LOG(ERROR) << "No keyset found for the given label: " << label;
    return nullptr;
  }
  return ConvertToAuthFactor(*vk);
}

user_data_auth::CryptohomeErrorCode
AuthFactorVaultKeysetConverter::VaultKeysetsToAuthFactorsAndKeyLabelData(
    const ObfuscatedUsername& obfuscated_username,
    std::vector<std::string>& migrated_labels,
    std::map<std::string, std::unique_ptr<AuthFactor>>&
        out_label_to_auth_factor,
    std::map<std::string, std::unique_ptr<AuthFactor>>&
        out_label_to_auth_factor_backup_vks) {
  DCHECK(out_label_to_auth_factor.empty());
  DCHECK(out_label_to_auth_factor_backup_vks.empty());
  DCHECK(migrated_labels.empty());

  std::vector<int> keyset_indices;
  if (!keyset_management_->GetVaultKeysets(obfuscated_username,
                                           &keyset_indices)) {
    LOG(WARNING) << "No valid keysets on disk for " << obfuscated_username;
    return user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND;
  }

  for (int index : keyset_indices) {
    std::unique_ptr<VaultKeyset> vk =
        keyset_management_->LoadVaultKeysetForUser(obfuscated_username, index);
    if (!vk) {
      continue;
    }

    // If there is any EasyUnlock keyset when loading the AuthFactor map,
    // we just want to delete it, not migrate to USS.
    std::string label = vk->GetLabel();
    if (label.rfind(kEasyUnlockLabelPrefix, 0) == 0) {
      // Remove and check that it has been removed.
      CryptohomeStatus status =
          keyset_management_->ForceRemoveKeyset(obfuscated_username, index);
      if (!status.ok()) {
        LOG(ERROR) << "RemoveKeysetByLabel: failed to remove keyset file for "
                      "EasyUnlock.";
      }
      continue;
    }

    std::unique_ptr<AuthFactor> auth_factor = ConvertToAuthFactor(*vk.get());
    if (!auth_factor) {
      continue;
    }

    // Select map to write the auth factor into.
    std::map<std::string, std::unique_ptr<AuthFactor>>& out_map =
        vk->IsForBackup() ? out_label_to_auth_factor_backup_vks
                          : out_label_to_auth_factor;

    auto [unused, was_inserted] =
        out_map.emplace(vk->GetLabel(), std::move(auth_factor));
    if (!was_inserted) {
      // This should not happen, but if somehow it does log it.
      const char* label_type = vk->IsForBackup() ? "backup " : "";
      LOG(ERROR) << "Found a duplicate " << label_type
                 << "label, skipping it: " << vk->GetLabel();
    }

    if (vk->IsMigrated()) {
      migrated_labels.push_back(vk->GetLabel());
    }
  }

  // Differentiate between no vault keyset case and vault keysets on the disk
  // but unable to be loaded case.
  if (out_label_to_auth_factor.empty() &&
      out_label_to_auth_factor_backup_vks.empty()) {
    return user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE;
  }

  return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
}

user_data_auth::CryptohomeErrorCode
AuthFactorVaultKeysetConverter::PopulateKeyDataForVK(
    const ObfuscatedUsername& obfuscated_username,
    const std::string& auth_factor_label,
    KeyData& out_vk_key_data) {
  std::unique_ptr<VaultKeyset> vk = keyset_management_->GetVaultKeyset(
      obfuscated_username, auth_factor_label);
  if (!vk) {
    LOG(ERROR) << "No keyset found for the label " << auth_factor_label;
    return user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND;
  }
  out_vk_key_data = vk->GetKeyDataOrDefault();

  return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
}

user_data_auth::CryptohomeErrorCode
AuthFactorVaultKeysetConverter::AuthFactorToKeyData(
    const std::string& auth_factor_label,
    const AuthFactorType& auth_factor_type,
    const AuthFactorMetadata& auth_factor_metadata,
    KeyData& out_key_data) {
  out_key_data.set_label(auth_factor_label);

  switch (auth_factor_type) {
    case AuthFactorType::kPassword:
      out_key_data.set_type(KeyData::KEY_TYPE_PASSWORD);
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    case AuthFactorType::kPin:
      out_key_data.set_type(KeyData::KEY_TYPE_PASSWORD);
      out_key_data.mutable_policy()->set_low_entropy_credential(true);
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    case AuthFactorType::kKiosk:
      out_key_data.set_type(KeyData::KEY_TYPE_KIOSK);
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    case AuthFactorType::kCryptohomeRecovery:
      return user_data_auth::CRYPTOHOME_ERROR_NOT_IMPLEMENTED;
    case AuthFactorType::kSmartCard: {
      out_key_data.set_type(KeyData::KEY_TYPE_CHALLENGE_RESPONSE);
      const auto* smart_card_metadata =
          std::get_if<auth_factor::SmartCardMetadata>(
              &auth_factor_metadata.metadata);
      if (!smart_card_metadata) {
        LOG(ERROR) << "Could not extract "
                      "auth_factor::SmartCardMetadata from "
                      "|auth_factor_metadata|";
        return user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT;
      }
      std::string public_key_string =
          brillo::BlobToString(smart_card_metadata->public_key_spki_der);
      auto* challenge_key = out_key_data.add_challenge_response_key();
      challenge_key->set_public_key_spki_der(public_key_string);
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    }
    case AuthFactorType::kLegacyFingerprint:
      LOG(ERROR) << "Verify-only fingerprints do not have key data";
      return user_data_auth::CRYPTOHOME_ERROR_NOT_IMPLEMENTED;
    case AuthFactorType::kFingerprint:
      LOG(ERROR) << "Fingerprint auth factor do not have key data";
      return user_data_auth::CRYPTOHOME_ERROR_NOT_IMPLEMENTED;
    case AuthFactorType::kUnspecified:
      LOG(ERROR) << "Unimplemented AuthFactorType.";
      return user_data_auth::CRYPTOHOME_ERROR_NOT_IMPLEMENTED;
  }
}

}  // namespace cryptohome
