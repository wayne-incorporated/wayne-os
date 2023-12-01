// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/keyring/real_keyring.h"

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/dircrypto_util.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/keyring.h"
#include "cryptohome/storage/keyring/utils.h"

using hwsec_foundation::SecureBlobToHex;

namespace cryptohome {

namespace {

bool AddEcryptfsKey(const FileSystemKey& key,
                    const FileSystemKeyReference& key_reference) {
  // Add the File Encryption key (FEK) from the vault keyset.  This is the key
  // that is used to encrypt the file contents when the file is persisted to the
  // lower filesystem by eCryptfs.
  auto key_signature = SecureBlobToHex(key_reference.fek_sig);
  if (!ecryptfs::AddEcryptfsAuthToken(key.fek, key_signature, key.fek_salt)) {
    LOG(ERROR) << "Couldn't add eCryptfs file encryption key to keyring.";
    return false;
  }

  // Add the File Name Encryption Key (FNEK) from the vault keyset.  This is the
  // key that is used to encrypt the file name when the file is persisted to the
  // lower filesystem by eCryptfs.
  auto filename_key_signature = SecureBlobToHex(key_reference.fnek_sig);
  if (!ecryptfs::AddEcryptfsAuthToken(key.fnek, filename_key_signature,
                                      key.fnek_salt)) {
    LOG(ERROR) << "Couldn't add eCryptfs filename encryption key to keyring.";
    return false;
  }
  return true;
}

bool RemoveEcryptfsKey(const FileSystemKeyReference& key_reference) {
  auto key_signature = SecureBlobToHex(key_reference.fek_sig);
  auto filename_key_signature = SecureBlobToHex(key_reference.fnek_sig);
  auto r1 = ecryptfs::RemoveEcryptfsAuthToken(key_signature);
  auto r2 = ecryptfs::RemoveEcryptfsAuthToken(filename_key_signature);
  return r1 && r2;
}

bool AddFscryptV1Key(const FileSystemKey& key,
                     const FileSystemKeyReference& key_reference) {
  dircrypto::KeyReference ref = {
      .policy_version = FSCRYPT_POLICY_V1,
      .reference = key_reference.fek_sig,
  };
  // V1 doesn't modify the reference.
  return dircrypto::AddDirectoryKey(key.fek, &ref);
}

bool RemoveFscryptV1Key(const FileSystemKeyReference& key_reference) {
  dircrypto::KeyReference ref = {
      .policy_version = FSCRYPT_POLICY_V1,
      .reference = key_reference.fek_sig,
  };
  return dircrypto::RemoveDirectoryKey(ref, base::FilePath());
}

bool AddFscryptV2Key(const FileSystemKey& key,
                     FileSystemKeyReference* key_reference) {
  dircrypto::KeyReference ref = {
      .policy_version = FSCRYPT_POLICY_V2,
      .reference = key_reference->fek_sig,
  };
  if (!dircrypto::AddDirectoryKey(key.fek, &ref)) {
    return false;
  }

  key_reference->fek_sig = ref.reference;
  return true;
}

bool RemoveFscryptV2Key(const FileSystemKeyReference& key_reference) {
  dircrypto::KeyReference ref = {
      .policy_version = FSCRYPT_POLICY_V2,
      .reference = key_reference.fek_sig,
  };
  return dircrypto::RemoveDirectoryKey(ref, base::FilePath());
}

bool AddDmcryptKey(const FileSystemKey& key,
                   FileSystemKeyReference* key_reference) {
  *key_reference = dmcrypt::GenerateKeyringDescription(key_reference->fek_sig);
  return dmcrypt::AddLogonKey(key.fek, key_reference->fek_sig);
}

bool RemoveDmcryptKey(const FileSystemKeyReference& key_reference) {
  return dmcrypt::UnlinkLogonKey(key_reference.fek_sig);
}

}  // namespace

bool RealKeyring::AddKey(Keyring::KeyType type,
                         const FileSystemKey& key,
                         FileSystemKeyReference* key_reference) {
  switch (type) {
    case Keyring::KeyType::kEcryptfsKey:
      return AddEcryptfsKey(key, *key_reference);
    case Keyring::KeyType::kFscryptV1Key:
      return AddFscryptV1Key(key, *key_reference);
    case Keyring::KeyType::kFscryptV2Key:
      return AddFscryptV2Key(key, key_reference);
    case Keyring::KeyType::kDmcryptKey:
      return AddDmcryptKey(key, key_reference);
  }
}

bool RealKeyring::RemoveKey(Keyring::KeyType type,
                            const FileSystemKeyReference& key_reference) {
  switch (type) {
    case Keyring::KeyType::kEcryptfsKey:
      return RemoveEcryptfsKey(key_reference);
    case Keyring::KeyType::kFscryptV1Key:
      return RemoveFscryptV1Key(key_reference);
    case Keyring::KeyType::kFscryptV2Key:
      return RemoveFscryptV2Key(key_reference);
    case Keyring::KeyType::kDmcryptKey:
      return RemoveDmcryptKey(key_reference);
  }
}

}  // namespace cryptohome
