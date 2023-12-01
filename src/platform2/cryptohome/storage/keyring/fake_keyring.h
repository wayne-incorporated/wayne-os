// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_KEYRING_FAKE_KEYRING_H_
#define CRYPTOHOME_STORAGE_KEYRING_FAKE_KEYRING_H_

#include "cryptohome/storage/keyring/keyring.h"

#include <algorithm>
#include <string>
#include <unordered_map>

#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>

#include "cryptohome/storage/encrypted_container/filesystem_key.h"

namespace cryptohome {

class FakeKeyring : public Keyring {
 public:
  FakeKeyring() = default;
  FakeKeyring(const FakeKeyring&) = delete;
  FakeKeyring& operator=(const FakeKeyring&) = delete;

  ~FakeKeyring() override = default;

  bool AddKey(Keyring::KeyType type,
              const FileSystemKey& key,
              FileSystemKeyReference* key_reference) override {
    if (ShouldFail()) {
      return false;
    }

    if (HasKey(type, *key_reference)) {
      return false;
    }

    // Ignore fnek in fake, since it doesn't really matter for anything but
    // ecryptfs.
    keys_.insert({MakeSignature(type, key_reference->fek_sig), key.fek});

    return true;
  }

  bool RemoveKey(Keyring::KeyType type,
                 const FileSystemKeyReference& key_reference) override {
    if (ShouldFail()) {
      return false;
    }

    if (!HasKey(type, key_reference)) {
      return true;
    }

    keys_.erase(MakeSignature(type, key_reference.fek_sig));
    return true;
  }

  bool HasKey(Keyring::KeyType type,
              const FileSystemKeyReference& key_reference) {
    return keys_.count(MakeSignature(type, key_reference.fek_sig));
  }

  void SetShouldFail(bool value) { should_fail_ = value; }

  void SetShouldFailAfter(int attempts) {
    should_fail_ = true;
    attempts_ = attempts;
  }

 private:
  static std::string MakeSignature(KeyType type,
                                   const brillo::SecureBlob& reference) {
    std::string key_name =
        base::ToLowerASCII(base::HexEncode(reference.data(), reference.size()));
    switch (type) {
      case Keyring::KeyType::kEcryptfsKey:
        return "ecryptfs-" + key_name;
      case Keyring::KeyType::kFscryptV1Key:
        return "fscryptv1-" + key_name;
      case Keyring::KeyType::kFscryptV2Key:
        return "fscryptv2-" + key_name;
      case Keyring::KeyType::kDmcryptKey:
        return "dmcrypt-" + key_name;
    }
  }

  bool ShouldFail() {
    if (should_fail_ && attempts_ <= 0) {
      return true;
    }
    attempts_ = std::max(0, attempts_ - 1);
    return false;
  }

  std::unordered_map<std::string, brillo::SecureBlob> keys_;
  bool should_fail_ = false;
  int attempts_ = 0;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_KEYRING_FAKE_KEYRING_H_
