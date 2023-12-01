// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/user_secret_stash/storage.h"

#include <sys/stat.h>

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"

using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::cryptohome::error::PrimaryAction;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::status::StatusChain;

namespace cryptohome {

// Use rw------- for the USS files.
constexpr mode_t kUserSecretStashFilePermissions = 0600;

UserSecretStashStorage::UserSecretStashStorage(Platform* platform)
    : platform_(platform) {}

UserSecretStashStorage::~UserSecretStashStorage() = default;

CryptohomeStatus UserSecretStashStorage::Persist(
    const brillo::Blob& uss_container_flatbuffer,
    const ObfuscatedUsername& obfuscated_username) {
  // TODO(b:232299885): Write to the next available slot, and clean up old slots
  // when necessary.
  const base::FilePath path =
      UserSecretStashPath(obfuscated_username, kUserSecretStashDefaultSlot);

  ReportTimerStart(kUSSPersistTimer);
  bool file_write_failure = !platform_->WriteFileAtomicDurable(
      path, uss_container_flatbuffer, kUserSecretStashFilePermissions);
  ReportTimerStop(kUSSPersistTimer);

  if (file_write_failure) {
    LOG(ERROR) << "Failed to store the UserSecretStash file for "
               << obfuscated_username;
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSStorageWriteFailedInPersist),
        ErrorActionSet({PossibleAction::kReboot,
                        PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  return OkStatus<CryptohomeError>();
}

CryptohomeStatusOr<brillo::Blob> UserSecretStashStorage::LoadPersisted(
    const ObfuscatedUsername& obfuscated_username) const {
  // TODO(b:232299885): Read from the latest available slot.
  const base::FilePath path =
      UserSecretStashPath(obfuscated_username, kUserSecretStashDefaultSlot);
  brillo::Blob uss_container_flatbuffer;

  ReportTimerStart(kUSSLoadPersistedTimer);
  bool file_read_failure =
      !platform_->ReadFile(path, &uss_container_flatbuffer);
  ReportTimerStop(kUSSLoadPersistedTimer);

  if (file_read_failure) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSStorageReadFailedInLoadPersisted),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kDeleteVault,
                        PossibleAction::kAuth,
                        PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  return uss_container_flatbuffer;
}

}  // namespace cryptohome
