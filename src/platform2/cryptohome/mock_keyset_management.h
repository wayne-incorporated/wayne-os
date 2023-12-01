// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_KEYSET_MANAGEMENT_H_
#define CRYPTOHOME_MOCK_KEYSET_MANAGEMENT_H_

#include "base/files/file_path.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/keyset_management.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <gmock/gmock.h>

#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/storage/file_system_keyset.h"

namespace cryptohome {
class VaultKeyset;
class HomeDirs;

typedef std::map<std::string, KeyData> KeyLabelMap;

class MockKeysetManagement : public KeysetManagement {
 public:
  MockKeysetManagement() = default;

  MOCK_METHOD(std::unique_ptr<VaultKeyset>,
              GetVaultKeyset,
              (const ObfuscatedUsername&, const std::string&),
              (const, override));
  MOCK_METHOD(bool,
              GetVaultKeysets,
              (const ObfuscatedUsername&, std::vector<int>*),
              (const, override));
  MOCK_METHOD(bool,
              GetVaultKeysetLabels,
              (const ObfuscatedUsername&, bool, std::vector<std::string>*),
              (const, override));
  MOCK_METHOD(CryptohomeStatus,
              ForceRemoveKeyset,
              (const ObfuscatedUsername&, int),
              (override));
  MOCK_METHOD(CryptohomeStatus,
              RemoveKeysetFile,
              (const VaultKeyset&),
              (override));
  MOCK_METHOD(void,
              RemoveLECredentials,
              (const ObfuscatedUsername&),
              (override));
  MOCK_METHOD(bool, UserExists, (const ObfuscatedUsername&), (override));
  MOCK_METHOD(std::unique_ptr<VaultKeyset>,
              LoadVaultKeysetForUser,
              (const ObfuscatedUsername&, int),
              (const, override));
  MOCK_METHOD(base::Time,
              GetKeysetBoundTimestamp,
              (const ObfuscatedUsername&),
              (override));
  MOCK_METHOD(void,
              CleanupPerIndexTimestampFiles,
              (const ObfuscatedUsername&),
              (override));
  MOCK_METHOD(bool,
              ShouldReSaveKeyset,
              (VaultKeyset * vault_keyset),
              (const, override));
  MOCK_METHOD(CryptohomeStatus,
              ReSaveKeyset,
              (VaultKeyset&, KeyBlobs, std::unique_ptr<AuthBlockState>),
              (const, override));
  MOCK_METHOD(MountStatusOr<std::unique_ptr<VaultKeyset>>,
              GetValidKeyset,
              (const ObfuscatedUsername&,
               KeyBlobs,
               const std::optional<std::string>&),
              (override));
  MOCK_METHOD(CryptohomeStatus,
              AddKeyset,
              (const VaultKeysetIntent&,
               const ObfuscatedUsername&,
               const std::string&,
               const KeyData&,
               const VaultKeyset&,
               KeyBlobs,
               std::unique_ptr<AuthBlockState>,
               bool clobber),
              (override));
  MOCK_METHOD(
      CryptohomeStatusOr<std::unique_ptr<VaultKeyset>>,
      AddInitialKeyset,
      (const VaultKeysetIntent& vk_intent,
       const ObfuscatedUsername&,
       const KeyData&,
       const std::optional<SerializedVaultKeyset_SignatureChallengeInfo>&,
       const FileSystemKeyset&,
       KeyBlobs,
       std::unique_ptr<AuthBlockState>),
      (override));
  MOCK_METHOD(bool,
              AddResetSeedIfMissing,
              (VaultKeyset & vault_keyset),
              (override));
  MOCK_METHOD(CryptohomeStatus,
              EncryptAndSaveKeyset,
              (VaultKeyset & vault_keyset,
               const KeyBlobs& key_blobs,
               const AuthBlockState& auth_state,
               const base::FilePath& save_path),
              (const, override));
  MOCK_METHOD(CryptohomeStatus,
              UpdateKeysetWithKeyBlobs,
              (const VaultKeysetIntent&,
               const ObfuscatedUsername&,
               const KeyData&,
               const VaultKeyset&,
               KeyBlobs,
               std::unique_ptr<AuthBlockState>),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_KEYSET_MANAGEMENT_H_
