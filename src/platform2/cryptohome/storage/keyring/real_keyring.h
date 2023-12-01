// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_KEYRING_REAL_KEYRING_H_
#define CRYPTOHOME_STORAGE_KEYRING_REAL_KEYRING_H_

#include "cryptohome/storage/keyring/keyring.h"

#include <brillo/secure_blob.h>
#include "cryptohome/storage/encrypted_container/filesystem_key.h"

namespace cryptohome {

class RealKeyring : public Keyring {
 public:
  RealKeyring() = default;
  RealKeyring(const RealKeyring&) = delete;
  RealKeyring& operator=(const RealKeyring&) = delete;

  ~RealKeyring() override = default;

  bool AddKey(Keyring::KeyType type,
              const FileSystemKey& key,
              FileSystemKeyReference* key_reference) override;
  bool RemoveKey(Keyring::KeyType type,
                 const FileSystemKeyReference& key_reference) override;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_KEYRING_REAL_KEYRING_H_
