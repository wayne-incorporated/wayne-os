// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/user_secret_stash/migrator.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/sha.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/reap.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/user_secret_stash/storage.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {

namespace {
using brillo::cryptohome::home::SanitizeUserName;
using cryptohome::error::CryptohomeError;
using cryptohome::error::ReapAndReportError;
using hwsec::StatusOr;
using hwsec_foundation::HmacSha256;
using hwsec_foundation::status::OkStatus;

constexpr char kMigrationSecretDerivationPublicInfo[] =
    "CHROMEOS_USS_MIGRATION_SECRET";
constexpr char kMigrationSecretLabel[] = "vk_to_uss_migration_secret_label";
}  // namespace

UssMigrator::UssMigrator(Username username) : username_(std::move(username)) {}

void UssMigrator::MigrateVaultKeysetToUss(
    const UserSecretStashStorage& user_secret_stash_storage,
    const std::string& label,
    const FileSystemKeyset& filesystem_keyset,
    CompletionCallback completion_callback) {
  // Create migration secret.
  GenerateMigrationSecret(filesystem_keyset);

  // Get the existing UserSecretStash and the main key if it exists, generate a
  // new UserSecretStash otherwise. This UserSecretStash will contain only one
  // key_block, with migration secret. The other key_blocks are added as the
  // credentials are migrated to AuthFactors and USS.

  // Load the USS container with the encrypted payload.
  std::unique_ptr<UserSecretStash> user_secret_stash;
  brillo::SecureBlob uss_main_key;
  CryptohomeStatusOr<brillo::Blob> encrypted_uss =
      user_secret_stash_storage.LoadPersisted(SanitizeUserName(username_));
  if (!encrypted_uss.ok()) {
    // If no UserSecretStash file found for the user create a new
    // UserSecretStash from the passed VaultKeyset and add the migration_secret
    // block.
    auto uss_status = UserSecretStash::CreateRandom(filesystem_keyset);
    if (!uss_status.ok()) {
      LOG(ERROR) << "UserSecretStash creation failed during migration of "
                    "VaultKeyset with label: "
                 << label;
      ReapAndReportError(std::move(uss_status).status(),
                         kCryptohomeErrorUssMigrationErrorBucket);
      ReportVkToUssMigrationStatus(VkToUssMigrationStatus::kFailedUssCreation);
      std::move(completion_callback)
          .Run(/*user_secret_stash=*/nullptr,
               /*uss_main_key=*/brillo::SecureBlob());
      return;
    }
    user_secret_stash = std::move(uss_status).value();
    uss_main_key = UserSecretStash::CreateRandomMainKey();
    if (!AddMigrationSecretToUss(uss_main_key, *user_secret_stash)) {
      ReportVkToUssMigrationStatus(
          VkToUssMigrationStatus::kFailedAddingMigrationSecret);
      std::move(completion_callback)
          .Run(/*user_secret_stash=*/nullptr,
               /*uss_main_key=*/brillo::SecureBlob());
      return;
    }
  } else {
    // Decrypt the existing UserSecretStash payload with the migration secret
    // and obtain the main key.
    auto uss_status = UserSecretStash::FromEncryptedContainerWithWrappingKey(
        encrypted_uss.value(),
        /*wrapping_id=*/kMigrationSecretLabel,
        /*wrapping_key=*/*migration_secret_, &uss_main_key);
    if (!uss_status.ok()) {
      LOG(ERROR) << "Failed to decrypt the UserSecretStash during migration.";
      ReapAndReportError(std::move(uss_status).status(),
                         kCryptohomeErrorUssMigrationErrorBucket);
      ReportVkToUssMigrationStatus(VkToUssMigrationStatus::kFailedUssDecrypt);
      std::move(completion_callback)
          .Run(/*user_secret_stash=*/nullptr,
               /*uss_main_key=*/brillo::SecureBlob());
      return;
    }
    user_secret_stash = std::move(uss_status).value();
  }

  std::move(completion_callback)
      .Run(std::move(user_secret_stash), std::move(uss_main_key));
}

void UssMigrator::GenerateMigrationSecret(
    const FileSystemKeyset& filesystem_keyset) {
  migration_secret_ = std::make_unique<brillo::SecureBlob>(
      HmacSha256(brillo::SecureBlob::Combine(filesystem_keyset.Key().fek,
                                             filesystem_keyset.Key().fnek),
                 brillo::BlobFromString(kMigrationSecretDerivationPublicInfo)));
}

bool UssMigrator::AddMigrationSecretToUss(
    const brillo::SecureBlob& uss_main_key,
    UserSecretStash& user_secret_stash) {
  // This wraps the USS Main Key with the migration_secret and adds the
  // migration_secret key block to USS in memory.
  CryptohomeStatus status = user_secret_stash.AddWrappedMainKey(
      uss_main_key,
      /*wrapping_id=*/kMigrationSecretLabel, *migration_secret_,
      OverwriteExistingKeyBlock::kDisabled);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to add the migration secret to the UserSecretStash.";
    ReapAndReportError(std::move(status),
                       kCryptohomeErrorUssMigrationErrorBucket);
    return false;
  }

  return true;
}

bool UssMigrator::RemoveMigrationSecretFromUss(
    UserSecretStash& user_secret_stash) {
  return user_secret_stash.RemoveWrappedMainKey(
      /*wrapping_id=*/kMigrationSecretLabel);
}

}  // namespace cryptohome
