// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTOHOME_KEY_LOADER_H_
#define CRYPTOHOME_CRYPTOHOME_KEY_LOADER_H_

#include <memory>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>

#include "cryptohome/platform.h"

namespace cryptohome {

class CryptohomeKeyLoader {
 public:
  CryptohomeKeyLoader(const hwsec::CryptohomeFrontend* frontend,
                      Platform* platform,
                      hwsec::KeyAlgoType key_algo,
                      const base::FilePath& path);
  CryptohomeKeyLoader(const CryptohomeKeyLoader&) = delete;
  CryptohomeKeyLoader& operator=(const CryptohomeKeyLoader&) = delete;

  virtual ~CryptohomeKeyLoader() = default;

  virtual bool HasCryptohomeKey();

  virtual hwsec::Key GetCryptohomeKey();

  virtual void Init();

 protected:
  // constructor for mock testing purpose.
  CryptohomeKeyLoader()
      : hwsec_(nullptr),
        platform_(nullptr),
        key_algo_(hwsec::KeyAlgoType::kRsa),
        cryptohome_key_path_() {}

 private:
  hwsec::StatusOr<hwsec::CryptohomeFrontend::CreateKeyResult>
  CreateCryptohomeKey();

  hwsec::Status SaveCryptohomeKey(const brillo::Blob& wrapped_key);

  hwsec::StatusOr<hwsec::ScopedKey> LoadCryptohomeKey();

  hwsec::StatusOr<hwsec::ScopedKey> LoadOrCreateCryptohomeKey();

  const hwsec::CryptohomeFrontend* const hwsec_;
  Platform* const platform_;
  const hwsec::KeyAlgoType key_algo_;
  const base::FilePath cryptohome_key_path_;
  std::optional<hwsec::ScopedKey> cryptohome_key_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTOHOME_KEY_LOADER_H_
