// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_ENCRYPTED_CONTAINER_FACTORY_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_ENCRYPTED_CONTAINER_FACTORY_H_

#include "cryptohome/storage/encrypted_container/encrypted_container.h"

#include <memory>

#include <base/files/file_path.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/backing_device_factory.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/keyring.h"

namespace cryptohome {

// `EncryptedContainerFactory` abstracts the creation of encrypted containers.
class EncryptedContainerFactory {
 public:
  explicit EncryptedContainerFactory(Platform* platform);
  EncryptedContainerFactory(
      Platform* platform,
      std::unique_ptr<Keyring> keyring,
      std::unique_ptr<BackingDeviceFactory> backing_device_factory);
  virtual ~EncryptedContainerFactory() {}

  virtual std::unique_ptr<EncryptedContainer> Generate(
      const EncryptedContainerConfig& config,
      const FileSystemKeyReference& key_reference);

  void set_allow_fscrypt_v2(bool allow_fscrypt_v2) {
    allow_fscrypt_v2_ = allow_fscrypt_v2;
  }

 private:
  Platform* platform_;
  std::unique_ptr<Keyring> keyring_;
  std::unique_ptr<BackingDeviceFactory> backing_device_factory_;
  bool allow_fscrypt_v2_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_ENCRYPTED_CONTAINER_FACTORY_H_
