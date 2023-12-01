// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_PKCS11_PKCS11_TOKEN_FACTORY_H_
#define CRYPTOHOME_PKCS11_PKCS11_TOKEN_FACTORY_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>

#include "cryptohome/pkcs11/pkcs11_token.h"
#include "cryptohome/username.h"

namespace cryptohome {

class Pkcs11TokenFactory {
 public:
  virtual ~Pkcs11TokenFactory() = default;
  virtual std::unique_ptr<Pkcs11Token> New(
      const Username& username,
      const base::FilePath& token_dir,
      const brillo::SecureBlob& auth_data) = 0;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PKCS11_PKCS11_TOKEN_FACTORY_H_
