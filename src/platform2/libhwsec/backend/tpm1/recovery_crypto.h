// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_RECOVERY_CRYPTO_H_
#define LIBHWSEC_BACKEND_TPM1_RECOVERY_CRYPTO_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/recovery_crypto.h"
#include "libhwsec/backend/tpm1/config.h"
#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/sealing.h"
#include "libhwsec/backend/tpm1/signing.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class RecoveryCryptoTpm1 : public RecoveryCrypto {
 public:
  RecoveryCryptoTpm1(overalls::Overalls& overalls,
                     ConfigTpm1& config,
                     KeyManagementTpm1& key_management,
                     SealingTpm1& sealing,
                     SigningTpm1& signing)
      : overalls_(overalls),
        config_(config),
        key_management_(key_management),
        sealing_(sealing),
        signing_(signing) {}

  StatusOr<std::optional<brillo::SecureBlob>> GenerateKeyAuthValue() override;
  StatusOr<EncryptEccPrivateKeyResponse> EncryptEccPrivateKey(
      const EncryptEccPrivateKeyRequest& request) override;
  StatusOr<crypto::ScopedEC_POINT> GenerateDiffieHellmanSharedSecret(
      const GenerateDhSharedSecretRequest& request) override;
  StatusOr<std::optional<RecoveryCryptoRsaKeyPair>> GenerateRsaKeyPair()
      override;
  StatusOr<std::optional<brillo::Blob>> SignRequestPayload(
      const brillo::Blob& encrypted_rsa_private_key,
      const brillo::Blob& request_payload) override;

 private:
  overalls::Overalls& overalls_;
  ConfigTpm1& config_;
  KeyManagementTpm1& key_management_;
  SealingTpm1& sealing_;
  Signing& signing_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_RECOVERY_CRYPTO_H_
