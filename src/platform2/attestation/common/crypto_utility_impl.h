// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_CRYPTO_UTILITY_IMPL_H_
#define ATTESTATION_COMMON_CRYPTO_UTILITY_IMPL_H_

#include "attestation/common/crypto_utility.h"

#include <string>

#include <crypto/scoped_openssl_types.h>
#include <libhwsec/frontend/attestation/frontend.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include "attestation/common/tpm_utility.h"

namespace attestation {

// An implementation of CryptoUtility.
class CryptoUtilityImpl : public CryptoUtility {
 public:
  // Does not take ownership of pointers.
  CryptoUtilityImpl(TpmUtility* tpm_utility,
                    const hwsec::AttestationFrontend* hwsec);
  ~CryptoUtilityImpl() override;

  // CryptoUtility methods.
  bool GetRandom(size_t num_bytes, std::string* random_data) const override;
  bool CreateSealedKey(std::string* aes_key, std::string* sealed_key) override;
  bool EncryptData(const std::string& data,
                   const std::string& aes_key,
                   const std::string& sealed_key,
                   std::string* encrypted_data) override;
  bool UnsealKey(const std::string& encrypted_data,
                 std::string* aes_key,
                 std::string* sealed_key) override;
  bool DecryptData(const std::string& encrypted_data,
                   const std::string& aes_key,
                   std::string* data) override;
  bool GetRSASubjectPublicKeyInfo(const std::string& public_key,
                                  std::string* spki) override;
  bool GetRSAPublicKey(const std::string& public_key_info,
                       std::string* public_key) override;
  bool EncryptIdentityCredential(
      TpmVersion tpm_version,
      const std::string& credential,
      const std::string& ek_public_key_info,
      const std::string& aik_public_key,
      EncryptedIdentityCredential* encrypted) override;
  bool DecryptIdentityCertificateForTpm2(
      const std::string& credential,
      const EncryptedData& encrypted_certificate,
      std::string* certificate) override;
  bool EncryptForUnbind(const std::string& public_key,
                        const std::string& data,
                        std::string* encrypted_data) override;
  bool VerifySignature(int digest_nid,
                       const std::string& public_key,
                       const std::string& data,
                       const std::string& signature) override;
  bool VerifySignatureUsingHexKey(int digest_nid,
                                  const std::string& public_key_hex,
                                  const std::string& data,
                                  const std::string& signature) override;
  bool EncryptDataForGoogle(const std::string& data,
                            const std::string& public_key_hex,
                            const std::string& key_id,
                            EncryptedData* encrypted_data) override;
  bool CreateSPKAC(const std::string& key_blob,
                   const std::string& public_key,
                   KeyType key_type,
                   std::string* spkac) override;
  bool VerifyCertificate(const std::string& certificate,
                         const std::string& ca_public_key_hex) override;
  bool VerifyCertificateWithSubjectPublicKey(
      const std::string& certificate,
      const std::string& ca_public_key_der_hex) override;
  bool GetCertificateIssuerName(const std::string& certificate,
                                std::string* issuer_name) override;
  bool GetCertificateSubjectPublicKeyInfo(const std::string& certificate,
                                          std::string* public_key) override;
  bool GetCertificatePublicKey(const std::string& certificate,
                               std::string* public_key) override;
  bool GetKeyDigest(const std::string& public_key,
                    std::string* key_digest) override;

  std::string HmacSha256(const std::string& key,
                         const std::string& data) override;

  std::string HmacSha512(const std::string& key,
                         const std::string& data) override;

  int DefaultDigestAlgoForSignature() override;

 private:
  friend class CryptoUtilityImplTest;

  enum class KeyDerivationScheme {
    // No derivation. The seed is used directly has both AES and HMAC keys. Not
    // recommended for new applications.
    kNone,
    // Derive using SHA-256 and the headers 'ENCRYPT' and 'MAC'.
    kHashWithHeaders,
  };

  // Encrypts |data| using |key|, |iv|, and the given |cipher|. Returns true on
  // success.
  bool AesEncrypt(const EVP_CIPHER* cipher,
                  const std::string& data,
                  const std::string& key,
                  const std::string& iv,
                  std::string* encrypted_data);

  // Decrypts |encrypted_data| using |key|, |iv|, and the given |cipher|.
  // Returns true on success.
  bool AesDecrypt(const EVP_CIPHER* cipher,
                  const std::string& encrypted_data,
                  const std::string& key,
                  const std::string& iv,
                  std::string* data);

  // Encrypt like trousers does. This is like AesEncrypt but a random IV is
  // included in the output.
  bool TssCompatibleEncrypt(const std::string& input,
                            const std::string& key,
                            std::string* output);

  // Encrypts using RSA-OAEP and the TPM-specific OAEP parameter.
  bool TpmCompatibleOAEPEncrypt(const std::string& input,
                                RSA* key,
                                std::string* output);

  // Encrypts |input| using AES-256-CBC-PKCS5, a random IV, and HMAC-SHA512 over
  // the cipher-text. The encryption and mac keys are derived from a |seed|
  // according to |derivation_scheme|. On success populates |seed| and |output|
  // and returns true. The output.wrapped_key and output.wrapping_key_id fields
  // are ignored.
  bool EncryptWithSeed(KeyDerivationScheme derivation_scheme,
                       const std::string& input,
                       const std::string& seed,
                       EncryptedData* encrypted);

  // Decrypts |input| using |seed| and |derivation_scheme|. On success populates
  // |decrypted| and returns true. This method is generally the inverse of
  // EncryptWithRandomKey() but the seed needs to be provided by the caller.
  bool DecryptWithSeed(KeyDerivationScheme derivation_scheme,
                       const EncryptedData& input,
                       const std::string& seed,
                       std::string* decrypted);

  // Wraps |key| with |wrapping_key| using RSA-PKCS1-OAEP. On success populates
  // output.wrapped_key and output.wrapping_key_id fields (other fields are
  // ignored).
  bool WrapKeyOAEP(const std::string& key,
                   RSA* wrapping_key,
                   const std::string& wrapping_key_id,
                   EncryptedData* output);

  // Computes a key 'Name' given a public key as a serialized TPMT_PUBLIC. The
  // name algorithm is assumed to be SHA256.
  std::string GetTpm2KeyNameFromPublicKey(
      const std::string& public_key_tpm_format);

  // Computes KDFa as defined in TPM 2.0 specification Part 1 Rev 1.16 Section
  // 11.4.9.1. It always uses SHA256 as the hash algorithm and outputs a 128-bit
  // or a 256-bit value, as defined by |bits|.
  std::string Tpm2CompatibleKDFa(const std::string& key,
                                 const std::string& label,
                                 const std::string& context,
                                 int bits);

  // Encrypts |input| using RSA-OAEP with a custom |label|. A zero byte will be
  // appended to the label as described in TPM 2.0 specification Part 1 Rev 1.16
  // Annex B.4.
  bool Tpm2CompatibleOAEPEncrypt(const std::string& label,
                                 const std::string& input,
                                 RSA* key,
                                 std::string* output);

  // Encrypts |input| using RSA-OAEP with a custom |label|.
  bool OAEPEncryptWithLabel(const std::string& label,
                            const std::string& input,
                            RSA* key,
                            const EVP_MD* md,
                            const EVP_MD* mgf1md,
                            std::string* output);

  // Verifies the |signature| for the provided |data| using the |key|.
  // The digest algorithm depends on OpenSSL nid |digest_nid|.
  bool VerifySignatureInner(int digest_nid,
                            const crypto::ScopedEVP_PKEY& key,
                            const std::string& data,
                            const std::string& signature);

  // Creates a SignedPublicKeyAndChallenge signed with |key_blob| from
  // |public_key| with a random challenge. On success returns true and provides
  // the |spkac|. |key_blob| is taken from the already loaded CertifiedKey and
  // |public_key| is the corresponding public part of |key_blob|.
  bool CreateSPKACInternal(const std::string& key_blob,
                           const crypto::ScopedEVP_PKEY& public_key,
                           std::string* spkac);

  TpmUtility* tpm_utility_;
  const hwsec::AttestationFrontend* hwsec_;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_CRYPTO_UTILITY_IMPL_H_
