// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_RECOVERY_CRYPTO_H_
#define LIBHWSEC_BACKEND_MOCK_RECOVERY_CRYPTO_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/recovery_crypto.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockRecoveryCrypto : public RecoveryCrypto {
 public:
  MockRecoveryCrypto() = default;
  explicit MockRecoveryCrypto(RecoveryCrypto* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, GenerateKeyAuthValue)
        .WillByDefault(Invoke(default_, &RecoveryCrypto::GenerateKeyAuthValue));
    ON_CALL(*this, EncryptEccPrivateKey)
        .WillByDefault(Invoke(default_, &RecoveryCrypto::EncryptEccPrivateKey));
    ON_CALL(*this, GenerateDiffieHellmanSharedSecret)
        .WillByDefault(Invoke(
            default_, &RecoveryCrypto::GenerateDiffieHellmanSharedSecret));
    ON_CALL(*this, GenerateRsaKeyPair)
        .WillByDefault(Invoke(default_, &RecoveryCrypto::GenerateRsaKeyPair));
    ON_CALL(*this, SignRequestPayload)
        .WillByDefault(Invoke(default_, &RecoveryCrypto::SignRequestPayload));
  }

  MOCK_METHOD(StatusOr<std::optional<brillo::SecureBlob>>,
              GenerateKeyAuthValue,
              (),
              (override));
  MOCK_METHOD(StatusOr<EncryptEccPrivateKeyResponse>,
              EncryptEccPrivateKey,
              (const EncryptEccPrivateKeyRequest& request),
              (override));
  MOCK_METHOD(StatusOr<crypto::ScopedEC_POINT>,
              GenerateDiffieHellmanSharedSecret,
              (const GenerateDhSharedSecretRequest& request),
              (override));
  MOCK_METHOD(StatusOr<std::optional<RecoveryCryptoRsaKeyPair>>,
              GenerateRsaKeyPair,
              (),
              (override));
  MOCK_METHOD(StatusOr<std::optional<brillo::Blob>>,
              SignRequestPayload,
              (const brillo::Blob& encrypted_rsa_private_key,
               const brillo::Blob& request_payload),
              (override));

 private:
  RecoveryCrypto* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_RECOVERY_CRYPTO_H_
