// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/backing_device_factory.h"
#include "cryptohome/storage/encrypted_container/dmcrypt_container.h"
#include "cryptohome/storage/encrypted_container/ecryptfs_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/ephemeral_container.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/encrypted_container/fscrypt_container.h"
#include "cryptohome/storage/keyring/keyring.h"
#include "cryptohome/storage/keyring/real_keyring.h"

namespace cryptohome {

EncryptedContainerFactory::EncryptedContainerFactory(Platform* platform)
    : EncryptedContainerFactory(
          platform,
          std::make_unique<RealKeyring>(),
          std::make_unique<BackingDeviceFactory>(platform)) {}

EncryptedContainerFactory::EncryptedContainerFactory(
    Platform* platform,
    std::unique_ptr<Keyring> keyring,
    std::unique_ptr<BackingDeviceFactory> backing_device_factory)
    : platform_(platform),
      keyring_(std::move(keyring)),
      backing_device_factory_(std::move(backing_device_factory)),
      allow_fscrypt_v2_(false) {}

std::unique_ptr<EncryptedContainer> EncryptedContainerFactory::Generate(
    const EncryptedContainerConfig& config,
    const FileSystemKeyReference& key_reference) {
  switch (config.type) {
    case EncryptedContainerType::kFscrypt:
      return std::make_unique<FscryptContainer>(
          config.backing_dir, key_reference, allow_fscrypt_v2_, platform_,
          keyring_.get());
    case EncryptedContainerType::kEcryptfs:
      return std::make_unique<EcryptfsContainer>(
          config.backing_dir, key_reference, platform_, keyring_.get());
    case EncryptedContainerType::kDmcrypt: {
      auto backing_device = backing_device_factory_->Generate(
          config.dmcrypt_config.backing_device_config);
      if (!backing_device) {
        LOG(ERROR) << "Could not create backing device for dmcrypt container";
        return nullptr;
      }
      return std::make_unique<DmcryptContainer>(
          config.dmcrypt_config, std::move(backing_device), key_reference,
          platform_, keyring_.get());
    }
    case EncryptedContainerType::kEphemeral: {
      auto backing_device =
          RamdiskDevice::Generate(config.backing_file_name, platform_);
      if (!backing_device) {
        LOG(ERROR) << "Could not create backing device for ephemeral container";
        return nullptr;
      }
      return std::make_unique<EphemeralContainer>(std::move(backing_device),
                                                  platform_);
    }
    case EncryptedContainerType::kEcryptfsToFscrypt:
    case EncryptedContainerType::kEcryptfsToDmcrypt:
    case EncryptedContainerType::kFscryptToDmcrypt:
      // The migrating type is handled by the higher level abstraction.
      // FALLTHROUGH
    case EncryptedContainerType::kUnknown:
      return nullptr;
  }
}

}  // namespace cryptohome
