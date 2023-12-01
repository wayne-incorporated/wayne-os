// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/recovery_crypto/frontend_impl.h"

#include <optional>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<std::optional<brillo::SecureBlob>>
RecoveryCryptoFrontendImpl::GenerateKeyAuthValue() const {
  return middleware_.CallSync<&Backend::RecoveryCrypto::GenerateKeyAuthValue>();
}

StatusOr<EncryptEccPrivateKeyResponse>
RecoveryCryptoFrontendImpl::EncryptEccPrivateKey(
    EncryptEccPrivateKeyRequest request) const {
  return middleware_.CallSync<&Backend::RecoveryCrypto::EncryptEccPrivateKey>(
      std::move(request));
}

StatusOr<crypto::ScopedEC_POINT>
RecoveryCryptoFrontendImpl::GenerateDiffieHellmanSharedSecret(
    GenerateDhSharedSecretRequest request) const {
  return middleware_
      .CallSync<&Backend::RecoveryCrypto::GenerateDiffieHellmanSharedSecret>(
          std::move(request));
}

StatusOr<std::optional<RecoveryCryptoRsaKeyPair>>
RecoveryCryptoFrontendImpl::GenerateRsaKeyPair() const {
  return middleware_.CallSync<&Backend::RecoveryCrypto::GenerateRsaKeyPair>();
}

StatusOr<std::optional<brillo::Blob>>
RecoveryCryptoFrontendImpl::SignRequestPayload(
    const brillo::Blob& encrypted_rsa_private_key,
    const brillo::Blob& request_payload) const {
  return middleware_.CallSync<&Backend::RecoveryCrypto::SignRequestPayload>(
      encrypted_rsa_private_key, request_payload);
}

}  // namespace hwsec
