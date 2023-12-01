// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/file_system_keyset.h"

#include <brillo/cryptohome.h>

#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include "cryptohome/cryptohome_common.h"

using brillo::SecureBlob;
using hwsec_foundation::CreateSecureRandomBlob;

namespace cryptohome {

FileSystemKeyset FileSystemKeyset::CreateRandom() {
  const FileSystemKey key = {
      .fek = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SIZE),
      .fnek = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SIZE),
      .fek_salt = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SALT_SIZE),
      .fnek_salt = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SALT_SIZE),
  };

  const FileSystemKeyReference key_reference = {
      .fek_sig = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE),
      .fnek_sig = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE),
  };

  const brillo::SecureBlob chaps_key =
      CreateSecureRandomBlob(CRYPTOHOME_CHAPS_KEY_LENGTH);

  return FileSystemKeyset(key, key_reference, chaps_key);
}

FileSystemKeyset::FileSystemKeyset() = default;
FileSystemKeyset::~FileSystemKeyset() = default;

FileSystemKeyset::FileSystemKeyset(const VaultKeyset& vault_keyset) {
  key_.fek = vault_keyset.GetFek();
  key_.fek_salt = vault_keyset.GetFekSalt();
  key_.fnek = vault_keyset.GetFnek();
  key_.fnek_salt = vault_keyset.GetFnekSalt();

  key_reference_.fek_sig = vault_keyset.GetFekSig();
  key_reference_.fnek_sig = vault_keyset.GetFnekSig();

  chaps_key_ = vault_keyset.GetChapsKey();
}

FileSystemKeyset::FileSystemKeyset(FileSystemKey key,
                                   FileSystemKeyReference key_reference,
                                   brillo::SecureBlob chaps_key)
    : key_(key), key_reference_(key_reference), chaps_key_(chaps_key) {}

const FileSystemKey& FileSystemKeyset::Key() const {
  return key_;
}

const FileSystemKeyReference& FileSystemKeyset::KeyReference() const {
  return key_reference_;
}

const brillo::SecureBlob& FileSystemKeyset::chaps_key() const {
  return chaps_key_;
}

}  // namespace cryptohome
