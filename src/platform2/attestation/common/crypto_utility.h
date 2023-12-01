// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_CRYPTO_UTILITY_H_
#define ATTESTATION_COMMON_CRYPTO_UTILITY_H_

#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/keystore.pb.h>

namespace attestation {

// A class which provides helpers for cryptography-related tasks.
class CryptoUtility {
 public:
  virtual ~CryptoUtility() = default;

  // Generates |num_bytes| of |random_data|. Returns true on success.
  virtual bool GetRandom(size_t num_bytes, std::string* random_data) const = 0;

  // Creates a random |aes_key| and seals it to the TPM's PCR0, producing a
  // |sealed_key|. Returns true on success.
  virtual bool CreateSealedKey(std::string* aes_key,
                               std::string* sealed_key) = 0;

  // Encrypts the given |data| using the |aes_key|. The |sealed_key| will be
  // embedded in the |encrypted_data| to assist with decryption. It can be
  // extracted from the |encrypted_data| using UnsealKey(). Returns true on
  // success.
  virtual bool EncryptData(const std::string& data,
                           const std::string& aes_key,
                           const std::string& sealed_key,
                           std::string* encrypted_data) = 0;

  // Extracts and unseals the |aes_key| from the |sealed_key| embedded in
  // the given |encrypted_data|. The |sealed_key| is also provided as an output
  // so callers can make subsequent calls to EncryptData() with the same key.
  // Returns true on success.
  virtual bool UnsealKey(const std::string& encrypted_data,
                         std::string* aes_key,
                         std::string* sealed_key) = 0;

  // Decrypts |encrypted_data| using |aes_key|, producing the decrypted |data|.
  // Returns true on success.
  virtual bool DecryptData(const std::string& encrypted_data,
                           const std::string& aes_key,
                           std::string* data) = 0;

  // Convert |public_key| from PKCS #1 RSAPublicKey to X.509
  // SubjectPublicKeyInfo. On success returns true and provides the
  // |public_key_info|.
  virtual bool GetRSASubjectPublicKeyInfo(const std::string& public_key,
                                          std::string* public_key_info) = 0;

  // Convert |public_key_info| from X.509 SubjectPublicKeyInfo to PKCS #1
  // RSAPublicKey. On success returns true and provides the |public_key|.
  virtual bool GetRSAPublicKey(const std::string& public_key_info,
                               std::string* public_key) = 0;

  // Encrypts a |credential| in a format compatible with TPM attestation key
  // activation. The |ek_public_key_info| must be provided in X.509
  // SubjectPublicKeyInfo format and the |aik_public_key| must be provided in
  // TPM_PUBKEY format (TPMT_PUBLIC for TPM 2.0).
  virtual bool EncryptIdentityCredential(
      TpmVersion tpm_version,
      const std::string& credential,
      const std::string& ek_public_key_info,
      const std::string& aik_public_key,
      EncryptedIdentityCredential* encrypted) = 0;

  // Decrypts an identity certificate given a 'credential' decrypted by the TPM
  // using TPM2_ActivateCredential.
  virtual bool DecryptIdentityCertificateForTpm2(
      const std::string& credential,
      const EncryptedData& encrypted_certificate,
      std::string* certificate) = 0;

  // Encrypts |data| in a format compatible with the TPM unbind operation. The
  // |public_key| must be provided in X.509 SubjectPublicKeyInfo format.
  virtual bool EncryptForUnbind(const std::string& public_key,
                                const std::string& data,
                                std::string* encrypted_data) = 0;

  // Verifies a |signature| over |data| with digest algorithm |digest_nid|.
  // The |public_key| must be provided in X.509 SubjectPublicKeyInfo format. The
  // format of |signature| can be PKCS #1 v1.5 for RSA, or OpenSSL DER format of
  // ECDSA.
  virtual bool VerifySignature(int digest_nid,
                               const std::string& public_key,
                               const std::string& data,
                               const std::string& signature) = 0;

  // Verifies a PKCS #1 v1.5 SHA-256 |signature| over |data| with digest
  // algorithm |digest_nid|. The |public_key_hex| contains a modulus in hex
  // format.
  virtual bool VerifySignatureUsingHexKey(int digest_nid,
                                          const std::string& public_key_hex,
                                          const std::string& data,
                                          const std::string& signature) = 0;

  // Encrypts |data| as expected by the Google ACA. |public_key_hex| is
  // a hex modulus and the |key_id| is opaque; these can change depending on
  // which instance of the ACA is used (e.g. production vs test). On success
  // returns true and populates |encrypted_data| which can be transmitted
  // to the ACA.
  virtual bool EncryptDataForGoogle(const std::string& certificate,
                                    const std::string& public_key_hex,
                                    const std::string& key_id,
                                    EncryptedData* encrypted_data) = 0;

  // Creates a SignedPublicKeyAndChallenge signed with |key_blob| from
  // |public_key| of |key_type| in DER format with a random challenge. On
  // success returns true and provides the |spkac|. |key_blob| and |public_key|
  // are taken from the already loaded CertifiedKey.
  //
  // Currently only RSA key type is supported.
  // TODO(b/140577280): Support ECC key.
  virtual bool CreateSPKAC(const std::string& key_blob,
                           const std::string& public_key,
                           KeyType key_type,
                           std::string* spkac) = 0;

  // Verifies that the X.509 |certificate| is signed by CA with the public key
  // with hex modulus |ca_public_key_hex|.
  virtual bool VerifyCertificate(const std::string& certificate,
                                 const std::string& ca_public_key_hex) = 0;

  // Verifies that the X.509 |certificate| is signed by CA with the public key
  // with |ca_public_key_der_hex|.
  virtual bool VerifyCertificateWithSubjectPublicKey(
      const std::string& certificate,
      const std::string& ca_public_key_der_hex) = 0;

  // Gets issuer name for the X.509 |certificate|. On success returns true and
  // populates |issuer_name|.
  virtual bool GetCertificateIssuerName(const std::string& certificate,
                                        std::string* issuer_name) = 0;

  // Gets SubjectPublicKeyInfo of public key for the X.509 |certificate|.
  // On success returns true and populates |public_key|.
  virtual bool GetCertificateSubjectPublicKeyInfo(
      const std::string& certificate, std::string* public_key) = 0;

  // Gets public key for the X.509 |certificate|. On success returns true and
  // populates |public_key|.
  virtual bool GetCertificatePublicKey(const std::string& certificate,
                                       std::string* public_key) = 0;

  // Calculates a SHA-1 |key_digest| over |public_key| modulus. The |public_key|
  // must be provided in X.509 SubjectPublicKeyInfo format.
  virtual bool GetKeyDigest(const std::string& public_key,
                            std::string* key_digest) = 0;

  // Computes and returns an HMAC of |data| using |key| and SHA-256.
  virtual std::string HmacSha256(const std::string& key,
                                 const std::string& data) = 0;

  // Computes and returns an HMAC of |data| using |key| and SHA-512.
  virtual std::string HmacSha512(const std::string& key,
                                 const std::string& data) = 0;

  // Get the default signature hash algorithm according to TPM version.
  // TPM 1.2 use SHA1. TPM 2.0 use SHA256.
  virtual int DefaultDigestAlgoForSignature() = 0;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_CRYPTO_UTILITY_H_
