// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_RECOVERY_CRYPTO_H_
#define LIBHWSEC_BACKEND_RECOVERY_CRYPTO_H_

#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"
#include "libhwsec/structures/operation_policy.h"
#include "libhwsec-foundation/crypto/elliptic_curve.h"

namespace hwsec {

// Recovery crypto backend input parameters for function EncryptEccPrivateKey.
struct EncryptEccPrivateKeyRequest {
  // Note: The EllipticCurve cannot be destructed before the call finished.
  const hwsec_foundation::EllipticCurve& ec;
  // Private key from one's own key pair would be imported to TPM2.0 or sealed
  // by TPM1.2.
  crypto::ScopedEC_KEY own_key_pair;
  // Additional secret to seal the destination share. Used for TPM 1.2 only.
  NoDefault<std::optional<brillo::SecureBlob>> auth_value;
  // The obfuscated username that key needs to be bound to.
  NoDefault<std::string> current_user;
};

// Recovery crypto backend output parameters for function EncryptEccPrivateKey.
struct EncryptEccPrivateKeyResponse {
  // One's own private key after imported/sealed to TPM.
  brillo::Blob encrypted_own_priv_key;
  // One's own private key after sealed to TPM1.2 with binding to extended PCR.
  brillo::Blob extended_pcr_bound_own_priv_key;
};

// Recovery crypto backend input parameters for function
// GenerateDiffieHellmanSharedSecret.
struct GenerateDhSharedSecretRequest {
  // Note: The EllipticCurve cannot be destructed before the call finished.
  const hwsec_foundation::EllipticCurve& ec;
  // One's own private key which is imported to TPM2.0 or sealed by TPM1.2.
  NoDefault<brillo::Blob> encrypted_own_priv_key;
  // One's own private key which is sealed by TPM1.2 and bound to extended PCR.
  NoDefault<brillo::Blob> extended_pcr_bound_own_priv_key;
  // Additional secret to Blob the destination share. Used for TPM 1.2 only.
  NoDefault<std::optional<brillo::SecureBlob>> auth_value;
  // The obfuscated username that key is bound to.
  NoDefault<std::string> current_user;
  // Public key from the other part, used to generate shared secret.
  crypto::ScopedEC_POINT others_pub_point;
};

// A Hardware-backed RSA key pair.
// The RSA private key would be used to sign recovery request payload
// when channel private key cannot be restored in a secure manner.
// Therefore, it will only be implemented in TPM1 backend.
struct RecoveryCryptoRsaKeyPair {
  // The encrypted private key for the RSA key pair.
  brillo::Blob encrypted_rsa_private_key;
  // The DER encoded SPKI format public key.
  brillo::Blob rsa_public_key_spki_der;
};

// RecoveryCrypto - class for performing cryptorecovery
// encryption/decryption in the secure hardware. For cryptorecovery, the
// secure hardware may be used as a way to strengthen the secret shares/
// private keys stored on disk.
class RecoveryCrypto {
 public:
  // Generate key_auth_value. key auth value is required for sealing/
  // unsealing in TPM1.2 only and the required length is 32 bytes. The
  // implementation for TPM2 backend will return std::nullopt.
  virtual StatusOr<std::optional<brillo::SecureBlob>>
  GenerateKeyAuthValue() = 0;

  // Encrypts the provided ECC private key using TPM, and returns it via
  // `encrypted_own_priv_key`, which is one's own private key. (the format of
  // this blob is TPM-specific). Returns false on failure.
  // As TPM1.2 does not support ECC, instead of encrypting the ECC private key,
  // it will seal the private key with the provided auth_value.
  virtual StatusOr<EncryptEccPrivateKeyResponse> EncryptEccPrivateKey(
      const EncryptEccPrivateKeyRequest& request) = 0;

  // Multiplies the private key, provided in encrypted form, with the given the
  // other party's public EC point. Returns the multiplication, or nullptr on
  // failure.
  // As TPM1.2 does not support ECC, instead of loading the ECC private key and
  // computing the shared secret from TPM modules, the private key will be
  // unsealed with the provided auth_value and the shared secret will be
  // computed via openssl lib.
  virtual StatusOr<crypto::ScopedEC_POINT> GenerateDiffieHellmanSharedSecret(
      const GenerateDhSharedSecretRequest& request) = 0;

  // Generate a TPM-backed RSA key pair.
  // Generated RSA private key would be used to sign recovery request payload
  // when channel private key cannot be restored in a secure manner.
  // Therefore, it will only be implemented in TPM1 backend. For TPM2, a dummy
  // std::nullopt would be returned.
  virtual StatusOr<std::optional<RecoveryCryptoRsaKeyPair>>
  GenerateRsaKeyPair() = 0;

  // Sign the request payload with the provided RSA private key. The RSA
  // private key would be loaded from the TPM modules first and used to sign
  // the payload. As signing the request payload is only required for TPM1,
  // the implementation of TPM2 would return a dummy std::nullopt.
  virtual StatusOr<std::optional<brillo::Blob>> SignRequestPayload(
      const brillo::Blob& encrypted_rsa_private_key,
      const brillo::Blob& request_payload) = 0;

 protected:
  RecoveryCrypto() = default;
  ~RecoveryCrypto() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_RECOVERY_CRYPTO_H_
