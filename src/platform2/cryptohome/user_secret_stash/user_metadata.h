// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SECRET_STASH_USER_METADATA_H_
#define CRYPTOHOME_USER_SECRET_STASH_USER_METADATA_H_

#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_container.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Interface for reading UserMetadata.
class UserMetadataReader {
 public:
  explicit UserMetadataReader(UserSecretStashStorage* storage);

  UserMetadataReader(const UserMetadataReader&) = delete;
  UserMetadataReader& operator=(const UserMetadataReader&) = delete;
  virtual ~UserMetadataReader() = default;

  // Attempt to load the metadata for the given user.
  virtual CryptohomeStatusOr<UserMetadata> Load(
      const ObfuscatedUsername& username);

 private:
  UserSecretStashStorage* storage_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SECRET_STASH_USER_METADATA_H_
