// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptohome_keys_manager.h"

#include <memory>

#include <base/logging.h>

#include "cryptohome/cryptohome_key_loader.h"

namespace cryptohome {

namespace {

constexpr char kDefaultCryptohomeRsaKeyFile[] = "/home/.shadow/cryptohome.key";
constexpr char kDefaultCryptohomeEccKeyFile[] =
    "/home/.shadow/cryptohome.ecc.key";

struct KeyLoaderInfo {
  hwsec::KeyAlgoType hwsec_type;
  CryptohomeKeyType cryptohome_type;
  const char* file_path;
};

KeyLoaderInfo kKeyLoadersList[] = {
    KeyLoaderInfo{
        .hwsec_type = hwsec::KeyAlgoType::kRsa,
        .cryptohome_type = CryptohomeKeyType::kRSA,
        .file_path = kDefaultCryptohomeRsaKeyFile,
    },
    KeyLoaderInfo{
        .hwsec_type = hwsec::KeyAlgoType::kEcc,
        .cryptohome_type = CryptohomeKeyType::kECC,
        .file_path = kDefaultCryptohomeEccKeyFile,
    },
};

}  // namespace

CryptohomeKeysManager::CryptohomeKeysManager(
    const hwsec::CryptohomeFrontend* hwsec, Platform* platform)
    : hwsec_(hwsec) {
  CHECK(hwsec);

  hwsec::StatusOr<absl::flat_hash_set<hwsec::KeyAlgoType>> algos =
      hwsec_->GetSupportedAlgo();
  if (!algos.ok()) {
    LOG(ERROR) << "Failed to get supported algorithms: " << algos.status();
    return;
  }

  for (const KeyLoaderInfo& info : kKeyLoadersList) {
    if (algos->count(info.hwsec_type) == 1) {
      key_loaders_[info.cryptohome_type] =
          std::make_unique<CryptohomeKeyLoader>(hwsec_, platform,
                                                info.hwsec_type,
                                                base::FilePath(info.file_path));
    }
  }
}

void CryptohomeKeysManager::Init() {
  for (auto& loader : key_loaders_) {
    loader.second->Init();
  }
}

CryptohomeKeyLoader* CryptohomeKeysManager::GetKeyLoader(
    CryptohomeKeyType key_type) {
  auto iter = key_loaders_.find(key_type);
  if (iter != key_loaders_.end()) {
    return iter->second.get();
  }
  return nullptr;
}

bool CryptohomeKeysManager::HasAnyCryptohomeKey() {
  for (auto& loader : key_loaders_) {
    if (loader.second->HasCryptohomeKey()) {
      return true;
    }
  }
  return false;
}

bool CryptohomeKeysManager::HasCryptohomeKey(CryptohomeKeyType key_type) {
  CryptohomeKeyLoader* key_loader = GetKeyLoader(key_type);
  return key_loader && key_loader->HasCryptohomeKey();
}

}  // namespace cryptohome
