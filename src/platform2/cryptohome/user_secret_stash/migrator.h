// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SECRET_STASH_MIGRATOR_H_
#define CRYPTOHOME_USER_SECRET_STASH_MIGRATOR_H_

#include <memory>
#include <string>

#include <base/functional/bind.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/username.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {

// This class object serves for migrating a user VaultKeyset to UserSecretStash
// and AuthFactor.
class UssMigrator {
 public:
  explicit UssMigrator(Username username);
  UssMigrator(const UssMigrator&) = delete;
  UssMigrator& operator=(const UssMigrator&) = delete;

  // Completes the UserSecretStash migration by persisting AuthFactor to
  // UserSecretStash and converting the VaultKeyset to a backup VaultKeyset.
  using CompletionCallback = base::OnceCallback<void(
      std::unique_ptr<UserSecretStash> user_secret_stash,
      brillo::SecureBlob uss_main_key)>;

  // The function that migrates the VaultKeyset with |label| and
  // |filesystem_keyset| to AuthFactor and USS.
  void MigrateVaultKeysetToUss(
      const UserSecretStashStorage& user_secret_stash_storage,
      const std::string& label,
      const FileSystemKeyset& filesystem_keyset,
      CompletionCallback completion_callback);

 private:
  // Generates migration secret from the filesystem keyset.
  void GenerateMigrationSecret(const FileSystemKeyset& filesystem_keyset);

  // Adds the migration secret as a |wrapped_key_block| to the given
  // user secret stash.
  bool AddMigrationSecretToUss(const brillo::SecureBlob& uss_main_key,
                               UserSecretStash& user_secret_stash);

  // Removes the |wrapped_key_block| corresponding to the migration secret from
  // the given user secret stash.
  bool RemoveMigrationSecretFromUss(UserSecretStash& user_secret_stash);

  Username username_;
  std::unique_ptr<brillo::SecureBlob> migration_secret_;
};

}  // namespace cryptohome
#endif  // CRYPTOHOME_USER_SECRET_STASH_MIGRATOR_H_
