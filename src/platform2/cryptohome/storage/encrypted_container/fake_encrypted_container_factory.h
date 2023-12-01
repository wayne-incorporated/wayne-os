// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FAKE_ENCRYPTED_CONTAINER_FACTORY_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FAKE_ENCRYPTED_CONTAINER_FACTORY_H_

#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/device_mapper_fake.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/dmcrypt_container.h"
#include "cryptohome/storage/encrypted_container/ecryptfs_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/fake_backing_device.h"
#include "cryptohome/storage/encrypted_container/fscrypt_container.h"
#include "cryptohome/storage/keyring/keyring.h"

namespace cryptohome {

// Fake for generating fake encrypted containers.
class FakeEncryptedContainerFactory : public EncryptedContainerFactory {
 public:
  explicit FakeEncryptedContainerFactory(Platform* platform,
                                         std::unique_ptr<Keyring> keyring)
      : EncryptedContainerFactory(platform),
        platform_(platform),
        keyring_(std::move(keyring)),
        backing_device_factory_(platform) {}

  ~FakeEncryptedContainerFactory() = default;

  std::unique_ptr<EncryptedContainer> Generate(
      const EncryptedContainerConfig& config,
      const FileSystemKeyReference& key_reference) override {
    return Generate(config, key_reference, /*create=*/false);
  }

  std::unique_ptr<EncryptedContainer> Generate(
      const EncryptedContainerConfig& config,
      const FileSystemKeyReference& key_reference,
      bool create) {
    std::unique_ptr<BackingDevice> backing_device;
    switch (config.type) {
      case EncryptedContainerType::kFscrypt:
        return std::make_unique<FscryptContainer>(
            config.backing_dir, key_reference,
            /*allow_v2=*/true, platform_, keyring_.get());
      case EncryptedContainerType::kEcryptfs:
        return std::make_unique<EcryptfsContainer>(
            config.backing_dir, key_reference, platform_, keyring_.get());
      case EncryptedContainerType::kDmcrypt:
        backing_device = backing_device_factory_.Generate(
            config.dmcrypt_config.backing_device_config);
        if (create)
          backing_device->Create();
        return std::make_unique<DmcryptContainer>(
            config.dmcrypt_config, std::move(backing_device), key_reference,
            platform_, keyring_.get(),
            std::make_unique<brillo::DeviceMapper>(
                base::BindRepeating(&brillo::fake::CreateDevmapperTask)));
      default:
        return nullptr;
    }
  }

 private:
  Platform* platform_;
  std::unique_ptr<Keyring> keyring_;
  FakeBackingDeviceFactory backing_device_factory_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FAKE_ENCRYPTED_CONTAINER_FACTORY_H_
