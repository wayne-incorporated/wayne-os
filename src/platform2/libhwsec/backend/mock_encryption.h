// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_ENCRYPTION_H_
#define LIBHWSEC_BACKEND_MOCK_ENCRYPTION_H_

#include <cstdint>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/encryption.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class MockEncryption : public Encryption {
 public:
  MockEncryption() = default;
  explicit MockEncryption(Encryption* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, Encrypt)
        .WillByDefault(Invoke(default_, &Encryption::Encrypt));
    ON_CALL(*this, Decrypt)
        .WillByDefault(Invoke(default_, &Encryption::Decrypt));
  }

  MOCK_METHOD(StatusOr<brillo::Blob>,
              Encrypt,
              (Key key,
               const brillo::SecureBlob& plaintext,
               EncryptionOptions options),
              (override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              Decrypt,
              (Key key,
               const brillo::Blob& ciphertext,
               EncryptionOptions options),
              (override));

 private:
  Encryption* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_ENCRYPTION_H_
