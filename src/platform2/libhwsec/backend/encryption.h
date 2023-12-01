// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_ENCRYPTION_H_
#define LIBHWSEC_BACKEND_ENCRYPTION_H_

#include <cstdint>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

// Encryption provide the functions to encrypt and decrypt blob.
class Encryption {
 public:
  struct EncryptionOptions {
    enum class Schema {
      kDefault,
      kNull,
      kRsaesSha1,
    };
    Schema schema = Schema::kDefault;
  };

  // Encrypts the |plaintext| with |key| and optional |options|.
  virtual StatusOr<brillo::Blob> Encrypt(Key key,
                                         const brillo::SecureBlob& plaintext,
                                         EncryptionOptions options) = 0;

  // Decrypts the |ciphertext| with |key| and optional |options|.
  virtual StatusOr<brillo::SecureBlob> Decrypt(Key key,
                                               const brillo::Blob& ciphertext,
                                               EncryptionOptions options) = 0;

 protected:
  Encryption() = default;
  ~Encryption() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_ENCRYPTION_H_
