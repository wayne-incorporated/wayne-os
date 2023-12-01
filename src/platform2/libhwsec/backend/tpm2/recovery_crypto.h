// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_RECOVERY_CRYPTO_H_
#define LIBHWSEC_BACKEND_TPM2_RECOVERY_CRYPTO_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/recovery_crypto.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/session_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"

namespace hwsec {

class RecoveryCryptoTpm2 : public RecoveryCrypto {
 public:
  RecoveryCryptoTpm2(TrunksContext& context,
                     ConfigTpm2& config,
                     KeyManagementTpm2& key_management,
                     SessionManagementTpm2& session_management)
      : context_(context),
        config_(config),
        key_management_(key_management),
        session_management_(session_management) {}

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
  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
  SessionManagementTpm2& session_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_RECOVERY_CRYPTO_H_
