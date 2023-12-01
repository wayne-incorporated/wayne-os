// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SECRET_STASH_STORAGE_H_
#define CRYPTOHOME_USER_SECRET_STASH_STORAGE_H_

#include <optional>
#include <string>

#include <brillo/secure_blob.h>

#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/platform.h"
#include "cryptohome/username.h"

namespace cryptohome {

class UserSecretStashStorage final {
 public:
  explicit UserSecretStashStorage(Platform* platform);

  UserSecretStashStorage(const UserSecretStashStorage&) = delete;
  UserSecretStashStorage& operator=(const UserSecretStashStorage&) = delete;

  ~UserSecretStashStorage();

  // Persists the serialized USS container, as created by
  // `UserSecretStash::GetEncryptedContainer()`, in the given user's directory
  // in the shadow root. Returns a status on failure.
  CryptohomeStatus Persist(const brillo::Blob& uss_container_flatbuffer,
                           const ObfuscatedUsername& obfuscated_username);
  // Loads the serialized USS container flatbuffer (to be used with
  // `UserSecretStash::FromEncryptedContainer()`) from the given user's
  // directory in the shadow root. Returns nullopt on failure.
  CryptohomeStatusOr<brillo::Blob> LoadPersisted(
      const ObfuscatedUsername& obfuscated_username) const;

 private:
  Platform* const platform_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SECRET_STASH_STORAGE_H_
