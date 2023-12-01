// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/fscrypt_container.h"

#include <base/files/file_path.h>
#include <base/logging.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/keyring.h"

namespace cryptohome {

FscryptContainer::FscryptContainer(const base::FilePath& backing_dir,
                                   const FileSystemKeyReference& key_reference,
                                   bool allow_v2,
                                   Platform* platform,
                                   Keyring* keyring)
    : backing_dir_(backing_dir),
      key_reference_(key_reference),
      allow_v2_(allow_v2),
      platform_(platform),
      keyring_(keyring) {}

bool FscryptContainer::Purge() {
  return platform_->DeletePathRecursively(backing_dir_);
}

bool FscryptContainer::Exists() {
  return platform_->DirectoryExists(backing_dir_) &&
         platform_->GetDirCryptoKeyState(backing_dir_) ==
             dircrypto::KeyState::ENCRYPTED;
}

bool FscryptContainer::Setup(const FileSystemKey& encryption_key) {
  if (!platform_->DirectoryExists(backing_dir_)) {
    if (!platform_->CreateDirectory(backing_dir_)) {
      LOG(ERROR) << "Failed to create directory " << backing_dir_;
      return false;
    }
  }

  auto key_type = UseV2() ? Keyring::KeyType::kFscryptV2Key
                          : Keyring::KeyType::kFscryptV1Key;
  if (!keyring_->AddKey(key_type, encryption_key, &key_reference_)) {
    LOG(ERROR) << "Failed to add fscrypt key to kernel";
    return false;
  }

  // `SetDirectoryKey` is a set-or-verify function: for directories with the
  // encryption policy already set, this function call acts as a verifier.
  dircrypto::KeyReference ref = {
      .policy_version = UseV2() ? FSCRYPT_POLICY_V2 : FSCRYPT_POLICY_V1,
      .reference = key_reference_.fek_sig,
  };
  if (!platform_->SetDirCryptoKey(backing_dir_, ref)) {
    LOG(ERROR) << "Failed to set fscrypt key for backing directory";
    return false;
  }

  return true;
}

bool FscryptContainer::Reset() {
  // Reset should never be called for fscrypt containers.
  LOG(ERROR) << "Reset not supported on fscrypt containers";
  return false;
}

bool FscryptContainer::Teardown() {
  auto key_type = UseV2() ? Keyring::KeyType::kFscryptV2Key
                          : Keyring::KeyType::kFscryptV1Key;
  return keyring_->RemoveKey(key_type, key_reference_);
}

base::FilePath FscryptContainer::GetBackingLocation() const {
  return backing_dir_;
}

bool FscryptContainer::UseV2() {
  auto existing_policy = platform_->GetDirectoryPolicyVersion(backing_dir_);
  if (existing_policy == FSCRYPT_POLICY_V1) {
    return false;
  }
  if (existing_policy == FSCRYPT_POLICY_V2) {
    return true;
  }
  return (allow_v2_ && platform_->CheckFscryptKeyIoctlSupport());
}

}  // namespace cryptohome
