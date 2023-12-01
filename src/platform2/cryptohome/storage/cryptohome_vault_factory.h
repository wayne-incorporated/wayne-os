// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_CRYPTOHOME_VAULT_FACTORY_H_
#define CRYPTOHOME_STORAGE_CRYPTOHOME_VAULT_FACTORY_H_

#include "cryptohome/storage/cryptohome_vault.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/username.h"

namespace cryptohome {

class CryptohomeVaultFactory {
 public:
  CryptohomeVaultFactory(
      Platform* platform,
      std::unique_ptr<EncryptedContainerFactory> encrypted_container_factory);

  virtual ~CryptohomeVaultFactory();

  virtual std::unique_ptr<CryptohomeVault> Generate(
      const ObfuscatedUsername& obfuscated_username,
      const FileSystemKeyReference& key_reference,
      EncryptedContainerType vault_type,
      bool keylocker_enabled = false);

  void set_enable_application_containers(bool value) {
    enable_application_containers_ = value;
  }

  // Cache objects for volume group and thinpool.
  void CacheLogicalVolumeObjects(std::optional<brillo::VolumeGroup> vg,
                                 std::optional<brillo::Thinpool> thinpool);

  bool ContainerExists(const std::string& container);

 private:
  struct DmOptions {
    bool keylocker_enabled = false;
    bool is_raw_device = false;
    uint32_t iv_offset = 0;
  };

  virtual std::unique_ptr<EncryptedContainer> GenerateEncryptedContainer(
      EncryptedContainerType type,
      const ObfuscatedUsername& obfuscated_username,
      const FileSystemKeyReference& key_reference,
      const std::string& container_identifier,
      const DmOptions& dm_options);

  Platform* platform_;
  std::unique_ptr<EncryptedContainerFactory> encrypted_container_factory_;
  bool enable_application_containers_;
  std::shared_ptr<brillo::VolumeGroup> vg_;
  std::shared_ptr<brillo::Thinpool> thinpool_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_CRYPTOHOME_VAULT_FACTORY_H_
