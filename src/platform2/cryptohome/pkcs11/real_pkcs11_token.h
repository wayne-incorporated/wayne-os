// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_PKCS11_REAL_PKCS11_TOKEN_H_
#define CRYPTOHOME_PKCS11_REAL_PKCS11_TOKEN_H_

#include "cryptohome/pkcs11/pkcs11_token.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>

#include "cryptohome/chaps_client_factory.h"
#include "cryptohome/username.h"

namespace cryptohome {

class RealPkcs11Token final : public Pkcs11Token {
 public:
  ~RealPkcs11Token() override;

  bool Insert() override;
  void Remove() override;
  bool IsReady() const override;

 private:
  RealPkcs11Token(const Username& username,
                  const base::FilePath& token_dir,
                  const brillo::SecureBlob& auth_data,
                  std::unique_ptr<ChapsClientFactory> chaps_client_factory =
                      std::make_unique<ChapsClientFactory>());

  const Username username_;
  const base::FilePath token_dir_;
  // Auth data is non-const for we have to reset it once used.
  brillo::SecureBlob auth_data_;

  const std::unique_ptr<ChapsClientFactory> chaps_client_factory_;

  bool ready_;

  friend class RealPkcs11TokenFactory;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PKCS11_REAL_PKCS11_TOKEN_H_
