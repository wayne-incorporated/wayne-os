// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FSCRYPT_CONTAINER_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FSCRYPT_CONTAINER_H_

#include "cryptohome/storage/encrypted_container/encrypted_container.h"

#include <base/files/file_path.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/keyring.h"

namespace cryptohome {

// `FscryptContainer` is a file-level encrypted container which uses fscrypt to
// encrypt the `backing_dir_` transparently.
class FscryptContainer : public EncryptedContainer {
 public:
  FscryptContainer(const base::FilePath& backing_dir,
                   const FileSystemKeyReference& key_reference,
                   bool allow_v2,
                   Platform* platform,
                   Keyring* keyring);
  ~FscryptContainer() = default;

  bool Setup(const FileSystemKey& encryption_key) override;
  bool Teardown() override;
  bool Exists() override;
  bool Reset() override;
  bool Purge() override;
  EncryptedContainerType GetType() const override {
    return EncryptedContainerType::kFscrypt;
  }
  base::FilePath GetBackingLocation() const override;

 private:
  // Deduces whether V1 or V2 policy should be used.
  bool UseV2();

  const base::FilePath backing_dir_;
  FileSystemKeyReference key_reference_;
  bool allow_v2_;
  Platform* platform_;
  Keyring* keyring_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FSCRYPT_CONTAINER_H_
