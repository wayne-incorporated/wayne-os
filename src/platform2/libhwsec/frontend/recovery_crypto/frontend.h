// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_RECOVERY_CRYPTO_FRONTEND_H_
#define LIBHWSEC_FRONTEND_RECOVERY_CRYPTO_FRONTEND_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/recovery_crypto.h"
#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class RecoveryCryptoFrontend : public Frontend {
 public:
  ~RecoveryCryptoFrontend() override = default;

  // Generate key_auth_value. key auth value is required for sealing/
  // unsealing in TPM1.2 only and the required length is 32 bytes. The
  // implementation for TPM2 backend will return std::nullopt.
  virtual StatusOr<std::optional<brillo::SecureBlob>> GenerateKeyAuthValue()
      const = 0;

  // Encrypts the provided ECC private key using TPM, and returns it via
  // `encrypted_own_priv_key`, which is one's own private key. (the format of
  // this blob is TPM-specific). Returns false on failure.
  // As TPM1.2 does not support ECC, instead of encrypting the ECC private
  // key, it will seal the private key with the provided auth_value in
  // operation policy.
  // Note: Because the request containing a crypto::ScopedEC_POINT, the request
  // cannot be copied, and must be moved into the function.
  virtual StatusOr<EncryptEccPrivateKeyResponse> EncryptEccPrivateKey(
      EncryptEccPrivateKeyRequest request) const = 0;

  // Multiplies the private key, provided in encrypted form, with the given
  // the other party's public EC point. Returns the multiplication, or nullptr
  // on failure. As TPM1.2 does not support ECC, instead of loading the ECC
  // private key and computing the shared secret from TPM modules, the private
  // key will be unsealed with the provided auth_value in operation policy and
  // the shared secret will be computed via openssl lib.
  // Note: Because the request containing a crypto::ScopedEC_KEY, the request
  // cannot be copied, and must be moved into the function.
  virtual StatusOr<crypto::ScopedEC_POINT> GenerateDiffieHellmanSharedSecret(
      GenerateDhSharedSecretRequest request) const = 0;

  // Generate a TPM-backed RSA key pair.
  // Generated RSA private key would be used to sign recovery request payload
  // when channel private key cannot be restored in a secure manner.
  // Therefore, it will only be implemented in TPM1 backend. For TPM2, a dummy
  // std::nullopt would be returned.
  virtual StatusOr<std::optional<RecoveryCryptoRsaKeyPair>> GenerateRsaKeyPair()
      const = 0;

  // Sign the request payload with the provided RSA private key. The RSA
  // private key would be loaded from the TPM modules first and used to sign
  // the payload. As signing the request payload is only required for TPM1,
  // the implementation of TPM2 would return a dummy std::nullopt.
  virtual StatusOr<std::optional<brillo::Blob>> SignRequestPayload(
      const brillo::Blob& encrypted_rsa_private_key,
      const brillo::Blob& request_payload) const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_RECOVERY_CRYPTO_FRONTEND_H_
