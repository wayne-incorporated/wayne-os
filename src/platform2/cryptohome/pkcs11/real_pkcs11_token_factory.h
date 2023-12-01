// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_PKCS11_REAL_PKCS11_TOKEN_FACTORY_H_
#define CRYPTOHOME_PKCS11_REAL_PKCS11_TOKEN_FACTORY_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>

#include "cryptohome/pkcs11/pkcs11_token_factory.h"
#include "cryptohome/pkcs11/real_pkcs11_token.h"

namespace cryptohome {

class RealPkcs11TokenFactory final : public Pkcs11TokenFactory {
 public:
  virtual ~RealPkcs11TokenFactory() = default;
  std::unique_ptr<Pkcs11Token> New(
      const Username& username,
      const base::FilePath& token_dir,
      const brillo::SecureBlob& auth_data) override {
    return std::unique_ptr<Pkcs11Token>(
        new RealPkcs11Token(username, token_dir, auth_data));
  }
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PKCS11_REAL_PKCS11_TOKEN_FACTORY_H_
