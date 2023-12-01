// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptohome_key_loader.h"

#include <utility>

#include <base/logging.h>
#include <libhwsec/status.h>

using brillo::Blob;
using hwsec::TPMError;
using hwsec::TPMErrorBase;
using hwsec::TPMRetryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
namespace cryptohome {

CryptohomeKeyLoader::CryptohomeKeyLoader(const hwsec::CryptohomeFrontend* hwsec,
                                         Platform* platform,
                                         hwsec::KeyAlgoType key_algo,
                                         const base::FilePath& path)
    : hwsec_(hwsec),
      platform_(platform),
      key_algo_(key_algo),
      cryptohome_key_path_(path) {
  CHECK(hwsec_);
  CHECK(platform_);
}

hwsec::Status CryptohomeKeyLoader::SaveCryptohomeKey(const Blob& wrapped_key) {
  if (!platform_->WriteFileAtomic(cryptohome_key_path_, wrapped_key, 0600)) {
    return MakeStatus<TPMError>("Error writing key file",
                                TPMRetryAction::kNoRetry);
  }
  return hwsec::OkStatus();
}

hwsec::StatusOr<hwsec::ScopedKey> CryptohomeKeyLoader::LoadCryptohomeKey() {
  // Load the key from the key file.
  Blob raw_key;
  if (!platform_->ReadFile(cryptohome_key_path_, &raw_key)) {
    return MakeStatus<TPMError>("Failed to read cryptohome key from file",
                                TPMRetryAction::kNoRetry);
  }

  hwsec::StatusOr<hwsec::ScopedKey> key = hwsec_->LoadKey(raw_key);
  if (!key.ok()) {
    return MakeStatus<TPMError>("Failed to load wrapped key")
        .Wrap(std::move(key).err_status());
  }

  return key;
}

hwsec::StatusOr<hwsec::ScopedKey>
CryptohomeKeyLoader::LoadOrCreateCryptohomeKey() {
  hwsec::StatusOr<bool> is_ready = hwsec_->IsReady();

  if (!is_ready.ok()) {
    return MakeStatus<TPMError>("Failed to get hwsec state")
        .Wrap(std::move(is_ready).err_status());
  }

  if (!*is_ready) {
    return MakeStatus<TPMError>(
        "Canceled loading cryptohome key - TPM is not ready",
        TPMRetryAction::kNoRetry);
  }

  // Try to load the cryptohome key.
  hwsec::StatusOr<hwsec::ScopedKey> key = LoadCryptohomeKey();
  if (!key.ok()) {
    if (key.err_status()->ToTPMRetryAction() == TPMRetryAction::kNoRetry) {
      // The key couldn't be loaded, and it wasn't due to a transient error,
      // so we must create the key.
      hwsec::StatusOr<hwsec::CryptohomeFrontend::CreateKeyResult> result =
          CreateCryptohomeKey();
      if (!result.ok()) {
        return MakeStatus<TPMError>("Failed to create cryptohome key")
            .Wrap(std::move(result).err_status());
      }

      if (hwsec::Status err = SaveCryptohomeKey(result->key_blob); !err.ok()) {
        return MakeStatus<TPMError>("Failed to save cryptohome key")
            .Wrap(std::move(err));
      }

      return std::move(result->key);
    }

    return MakeStatus<TPMError>("Failed to load cryptohome key")
        .Wrap(std::move(key).err_status());
  }

  return key;
}

hwsec::StatusOr<hwsec::CryptohomeFrontend::CreateKeyResult>
CryptohomeKeyLoader::CreateCryptohomeKey() {
  return hwsec_->CreateCryptohomeKey(key_algo_);
}

bool CryptohomeKeyLoader::HasCryptohomeKey() {
  return cryptohome_key_.has_value();
}

hwsec::Key CryptohomeKeyLoader::GetCryptohomeKey() {
  return cryptohome_key_->GetKey();
}

void CryptohomeKeyLoader::Init() {
  hwsec::StatusOr<hwsec::ScopedKey> key = LoadOrCreateCryptohomeKey();
  if (!key.ok()) {
    LOG(ERROR) << "Failed to load or create cryptohome key: " << key.status();
    return;
  }

  cryptohome_key_ = std::move(*key);
}

}  // namespace cryptohome
