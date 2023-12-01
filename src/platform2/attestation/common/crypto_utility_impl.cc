// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/crypto_utility_impl.h"

#include <iterator>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/secure_util.h>
#include <crypto/sha2.h>
#include <libhwsec/frontend/attestation/frontend.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

using ::hwsec::TPMError;

namespace {

const size_t kAesKeySize = 32;
const size_t kAesBlockSize = 16;
const char kHashHeaderForEncrypt[] = "ENCRYPT";
const char kHashHeaderForMac[] = "MAC";
const unsigned int kWellKnownExponent = 65537;

std::string GetOpenSSLError() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* data = nullptr;
  int data_len = BIO_get_mem_data(bio, &data);
  std::string error_string(data, data_len);
  BIO_free(bio);
  return error_string;
}

unsigned char* StringAsOpenSSLBuffer(std::string* s) {
  return reinterpret_cast<unsigned char*>(std::data(*s));
}

const unsigned char* StringAsConstOpenSSLBuffer(const std::string& s) {
  return reinterpret_cast<const unsigned char*>(s.data());
}

crypto::ScopedRSA CreateRSAFromHexModulus(const std::string& hex_modulus) {
  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new()), n(BN_new());
  if (!rsa || !e || !n) {
    LOG(ERROR) << __func__ << ": Failed to allocate RSA or BIGNUMs.";
    return nullptr;
  }
  BIGNUM* pn = n.get();
  if (!BN_set_word(e.get(), kWellKnownExponent) ||
      !BN_hex2bn(&pn, hex_modulus.c_str())) {
    LOG(ERROR) << __func__ << ": Failed to generate exponent or modulus.";
    return nullptr;
  }
  if (!RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr)) {
    LOG(ERROR) << __func__ << ": Failed to set exponent or modulus.";
    return nullptr;
  }
  return rsa;
}

crypto::ScopedOpenSSL<X509, X509_free> CreateX509FromCertificate(
    const std::string& certificate) {
  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(certificate.data());
  crypto::ScopedOpenSSL<X509, X509_free> x509(
      d2i_X509(NULL, &asn1_ptr, certificate.size()));
  return x509;
}

}  // namespace

namespace attestation {

CryptoUtilityImpl::CryptoUtilityImpl(TpmUtility* tpm_utility,
                                     const hwsec::AttestationFrontend* hwsec)
    : tpm_utility_(tpm_utility), hwsec_(hwsec) {
  CHECK(hwsec_);
  OpenSSL_add_all_algorithms();
  EVP_PKEY_asn1_add_alias(EVP_PKEY_RSA, NID_rsaesOaep);
  ERR_load_crypto_strings();
}

CryptoUtilityImpl::~CryptoUtilityImpl() {
  EVP_cleanup();
  ERR_free_strings();
}

bool CryptoUtilityImpl::GetRandom(size_t num_bytes,
                                  std::string* random_data) const {
  // OpenSSL takes a signed integer.
  if (num_bytes > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  random_data->resize(num_bytes);
  unsigned char* buffer = StringAsOpenSSLBuffer(random_data);
  return (RAND_bytes(buffer, num_bytes) == 1);
}

bool CryptoUtilityImpl::CreateSealedKey(std::string* aes_key,
                                        std::string* sealed_key) {
  if (!GetRandom(kAesKeySize, aes_key)) {
    LOG(ERROR) << __func__ << ": GetRandom failed.";
    return false;
  }
  ASSIGN_OR_RETURN(
      const brillo::Blob& sealed_key_blob,
      hwsec_->Seal(brillo::SecureBlob(*aes_key)),
      _.WithStatus<TPMError>("Failed to seal aes key").LogError().As(false));
  *sealed_key = brillo::BlobToString(sealed_key_blob);
  return true;
}

bool CryptoUtilityImpl::EncryptData(const std::string& data,
                                    const std::string& aes_key,
                                    const std::string& sealed_key,
                                    std::string* encrypted_data) {
  EncryptedData encrypted_pb;
  encrypted_pb.set_wrapped_key(sealed_key);
  if (!EncryptWithSeed(KeyDerivationScheme::kNone, data, aes_key,
                       &encrypted_pb)) {
    return false;
  }
  if (!encrypted_pb.SerializeToString(encrypted_data)) {
    LOG(ERROR) << __func__ << ": Failed to serialize protobuf.";
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::UnsealKey(const std::string& encrypted_data,
                                  std::string* aes_key,
                                  std::string* sealed_key) {
  EncryptedData encrypted_pb;
  if (!encrypted_pb.ParseFromString(encrypted_data)) {
    LOG(ERROR) << __func__ << ": Failed to parse protobuf.";
    return false;
  }
  ASSIGN_OR_RETURN(
      const brillo::SecureBlob& aes_key_blob,
      hwsec_->Unseal(brillo::BlobFromString(encrypted_pb.wrapped_key())),
      _.WithStatus<TPMError>("Failed to unseal aes key").LogError().As(false));
  *aes_key = aes_key_blob.to_string();
  *sealed_key = encrypted_pb.wrapped_key();
  return true;
}

bool CryptoUtilityImpl::DecryptData(const std::string& encrypted_data,
                                    const std::string& aes_key,
                                    std::string* data) {
  EncryptedData encrypted_pb;
  if (!encrypted_pb.ParseFromString(encrypted_data)) {
    LOG(ERROR) << __func__ << ": Failed to parse protobuf.";
    return false;
  }
  return DecryptWithSeed(KeyDerivationScheme::kNone, encrypted_pb, aes_key,
                         data);
}

bool CryptoUtilityImpl::GetRSASubjectPublicKeyInfo(
    const std::string& public_key, std::string* public_key_info) {
  auto asn1_ptr = reinterpret_cast<const unsigned char*>(public_key.data());
  crypto::ScopedRSA rsa(
      d2i_RSAPublicKey(nullptr, &asn1_ptr, public_key.size()));
  if (!rsa.get()) {
    LOG(ERROR) << __func__
               << ": Failed to decode public key: " << GetOpenSSLError();
    return false;
  }
  unsigned char* buffer = nullptr;
  int length = i2d_RSA_PUBKEY(rsa.get(), &buffer);
  if (length <= 0) {
    LOG(ERROR) << __func__
               << ": Failed to encode public key: " << GetOpenSSLError();
    return false;
  }
  crypto::ScopedOpenSSLBytes scoped_buffer(buffer);
  public_key_info->assign(reinterpret_cast<char*>(buffer), length);
  return true;
}

bool CryptoUtilityImpl::GetRSAPublicKey(const std::string& public_key_info,
                                        std::string* public_key) {
  auto asn1_ptr =
      reinterpret_cast<const unsigned char*>(public_key_info.data());
  crypto::ScopedRSA rsa(
      d2i_RSA_PUBKEY(NULL, &asn1_ptr, public_key_info.size()));
  if (!rsa.get()) {
    LOG(ERROR) << __func__
               << ": Failed to decode public key: " << GetOpenSSLError();
    return false;
  }
  unsigned char* buffer = NULL;
  int length = i2d_RSAPublicKey(rsa.get(), &buffer);
  if (length <= 0) {
    LOG(ERROR) << __func__
               << ": Failed to encode public key: " << GetOpenSSLError();
    return false;
  }
  crypto::ScopedOpenSSLBytes scoped_buffer(buffer);
  public_key->assign(reinterpret_cast<char*>(buffer), length);
  return true;
}

bool CryptoUtilityImpl::EncryptIdentityCredential(
    TpmVersion tpm_version,
    const std::string& credential,
    const std::string& ek_public_key_info,
    const std::string& aik_public_key,
    EncryptedIdentityCredential* encrypted) {
  auto asn1_ptr =
      reinterpret_cast<const unsigned char*>(ek_public_key_info.data());
  encrypted->set_tpm_version(tpm_version);
  if (tpm_version == TPM_1_2) {
    // TODO(crbug/942487): Only use d2i_RSA_PUBKEY for both TPM version and move
    // it back to the start of this function after the bug is resolved.
    crypto::ScopedRSA rsa(
        d2i_RSAPublicKey(NULL, &asn1_ptr, ek_public_key_info.size()));
    if (!rsa.get()) {
      LOG(ERROR) << __func__
                 << ": Failed to decode EK public key: " << GetOpenSSLError();
      return false;
    }
    const char kAlgAES256 = 9;   // This comes from TPM_ALG_AES256.
    const char kEncModeCBC = 2;  // This comes from TPM_SYM_MODE_CBC.
    const char kAsymContentHeader[] = {0, 0,           0, kAlgAES256,
                                       0, kEncModeCBC, 0, kAesKeySize};
    const char kSymContentHeader[12] = {};

    // Generate an AES key and encrypt the credential.
    std::string aes_key;
    if (!GetRandom(kAesKeySize, &aes_key)) {
      LOG(ERROR) << __func__ << ": GetRandom failed.";
      return false;
    }
    std::string encrypted_credential;
    if (!TssCompatibleEncrypt(credential, aes_key, &encrypted_credential)) {
      LOG(ERROR) << __func__ << ": Failed to encrypt credential.";
      return false;
    }

    // Construct a TPM_ASYM_CA_CONTENTS structure.
    std::string asym_header(std::begin(kAsymContentHeader),
                            std::end(kAsymContentHeader));
    std::string asym_content =
        asym_header + aes_key + base::SHA1HashString(aik_public_key);

    // Encrypt the TPM_ASYM_CA_CONTENTS with the EK public key.
    std::string encrypted_asym_content;
    if (!TpmCompatibleOAEPEncrypt(asym_content, rsa.get(),
                                  &encrypted_asym_content)) {
      LOG(ERROR) << __func__ << ": Failed to encrypt with EK public key.";
      return false;
    }

    // Construct a TPM_SYM_CA_ATTESTATION structure.
    uint32_t length = htonl(encrypted_credential.size());
    auto length_bytes = reinterpret_cast<const char*>(&length);
    std::string length_blob(length_bytes, sizeof(uint32_t));
    std::string sym_header(std::begin(kSymContentHeader),
                           std::end(kSymContentHeader));
    std::string sym_content = length_blob + sym_header + encrypted_credential;

    encrypted->set_asym_ca_contents(encrypted_asym_content);
    encrypted->set_sym_ca_attestation(sym_content);
  } else if (tpm_version == TPM_2_0) {
    crypto::ScopedRSA rsa(
        d2i_RSA_PUBKEY(NULL, &asn1_ptr, ek_public_key_info.size()));
    if (!rsa.get()) {
      LOG(ERROR) << __func__
                 << ": Failed to decode EK public key: " << GetOpenSSLError();
      return false;
    }
    // The 'credential' parameter is actually the certificate. The 'credential'
    // used in the wrapping process is referred to as 'inner_credential' below.
    std::string certificate = credential;
    // Generate a random seed and derive from it an AES and HMAC key as
    // documented in TPM 2.0 specification Part 1 Rev 1.16 Section 24.
    std::string seed;
    if (!GetRandom(kAesKeySize, &seed)) {
      return false;
    }
    std::string identity_key_name = GetTpm2KeyNameFromPublicKey(aik_public_key);
    std::string aes_key =
        Tpm2CompatibleKDFa(seed, "STORAGE", identity_key_name, 128);
    std::string hmac_key = Tpm2CompatibleKDFa(seed, "INTEGRITY", "", 256);
    // This will be the 'credential' that the TPM decrypts during activation.
    std::string inner_credential;
    if (!GetRandom(kAesKeySize, &inner_credential)) {
      return false;
    }
    // Wrap the credential with the seed using an Encrypt-then-MAC scheme
    // documented in TPM 2.0 specification Part 1 Rev 1.16 Section 24.
    std::string encrypted_credential;
    std::string iv(kAesBlockSize, 0);
    std::string inner_credential_size_bytes("\x00\x20", 2);  // Big-endian 32.
    if (!AesEncrypt(EVP_aes_128_cfb(),
                    inner_credential_size_bytes + inner_credential, aes_key, iv,
                    &encrypted_credential)) {
      return false;
    }
    encrypted->set_credential_mac(
        HmacSha256(hmac_key, encrypted_credential + identity_key_name));
    // Wrap the certificate with the credential using the scheme required by the
    // EncryptedIdentityCredential protobuf.
    EncryptedData* encrypted_certificate =
        encrypted->mutable_wrapped_certificate();
    if (!EncryptWithSeed(KeyDerivationScheme::kHashWithHeaders, certificate,
                         inner_credential, encrypted_certificate)) {
      return false;
    }
    encrypted_certificate->set_wrapped_key(encrypted_credential);
    // At this point, the credential can be recovered given the seed, and the
    // certificate can be recovered given the credential. All that remains is to
    // encrypt the seed with the EK public key.
    if (!Tpm2CompatibleOAEPEncrypt("IDENTITY", seed, rsa.get(),
                                   encrypted->mutable_encrypted_seed())) {
      return false;
    }
  } else {
    LOG(ERROR) << "Unsupported TPM version.";
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::DecryptIdentityCertificateForTpm2(
    const std::string& credential,
    const EncryptedData& encrypted_certificate,
    std::string* certificate) {
  return DecryptWithSeed(KeyDerivationScheme::kHashWithHeaders,
                         encrypted_certificate, credential, certificate);
}

bool CryptoUtilityImpl::EncryptForUnbind(const std::string& public_key,
                                         const std::string& data,
                                         std::string* encrypted_data) {
  // Construct a TPM_BOUND_DATA structure.
  const char kBoundDataHeader[] = {1, 1, 0, 0, 2 /* TPM_PT_BIND */};
  std::string header(std::begin(kBoundDataHeader), std::end(kBoundDataHeader));
  std::string bound_data = header + data;

  // Encrypt using the TPM_ES_RSAESOAEP_SHA1_MGF1 scheme.
  auto asn1_ptr = reinterpret_cast<const unsigned char*>(public_key.data());
  crypto::ScopedRSA rsa(d2i_RSA_PUBKEY(NULL, &asn1_ptr, public_key.size()));
  if (!rsa.get()) {
    LOG(ERROR) << __func__
               << ": Failed to decode public key: " << GetOpenSSLError();
    return false;
  }
  if (!TpmCompatibleOAEPEncrypt(bound_data, rsa.get(), encrypted_data)) {
    LOG(ERROR) << __func__ << ": Failed to encrypt with public key.";
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::VerifySignature(int digest_nid,
                                        const std::string& public_key,
                                        const std::string& data,
                                        const std::string& signature) {
  auto asn1_ptr = reinterpret_cast<const unsigned char*>(public_key.data());
  crypto::ScopedEVP_PKEY pubkey(d2i_PUBKEY(NULL, &asn1_ptr, public_key.size()));
  if (!pubkey.get()) {
    LOG(ERROR) << __func__
               << ": Failed to decode public key: " << GetOpenSSLError();
    return false;
  }
  return VerifySignatureInner(digest_nid, pubkey, data, signature);
}

bool CryptoUtilityImpl::VerifySignatureUsingHexKey(
    int digest_nid,
    const std::string& public_key_hex,
    const std::string& data,
    const std::string& signature) {
  crypto::ScopedRSA rsa = CreateRSAFromHexModulus(public_key_hex);
  if (!rsa.get()) {
    LOG(ERROR) << __func__ << ": Failed to decode public key.";
    return false;
  }

  crypto::ScopedEVP_PKEY evp_pkey(EVP_PKEY_new());
  if (!evp_pkey.get()) {
    LOG(ERROR) << __func__ << ": Failed to allocate EVP PKEY.";
    return false;
  }
  EVP_PKEY_assign_RSA(evp_pkey.get(), rsa.release());
  return VerifySignatureInner(digest_nid, evp_pkey, data, signature);
}

bool CryptoUtilityImpl::VerifySignatureInner(
    int digest_nid,
    const crypto::ScopedEVP_PKEY& pubkey,
    const std::string& data,
    const std::string& signature) {
  const EVP_MD* md = EVP_get_digestbynid(digest_nid);
  if (md == nullptr) {
    LOG(ERROR) << __func__ << ": Failed to get hash algorithm from digest NID: "
               << digest_nid;
    return false;
  }

  crypto::ScopedEVP_MD_CTX mdctx(EVP_MD_CTX_new());
  if (!mdctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_MD_CTX: " << GetOpenSSLError();
    return false;
  }
  if (!EVP_DigestVerifyInit(mdctx.get(), nullptr, md, nullptr, pubkey.get())) {
    LOG(ERROR) << __func__ << ": Failed to initialize verifying process: "
               << GetOpenSSLError();
    return false;
  }

  if (!EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.length())) {
    LOG(ERROR) << __func__
               << ": Failed to hash the input data: " << GetOpenSSLError();
    return false;
  }

  return EVP_DigestVerifyFinal(
      mdctx.get(), StringAsConstOpenSSLBuffer(signature), signature.size());
}

bool CryptoUtilityImpl::EncryptDataForGoogle(const std::string& data,
                                             const std::string& public_key_hex,
                                             const std::string& key_id,
                                             EncryptedData* encrypted_data) {
  crypto::ScopedRSA rsa = CreateRSAFromHexModulus(public_key_hex);
  if (!rsa.get()) {
    LOG(ERROR) << __func__ << ": Failed to decode public key.";
    return false;
  }
  std::string key;
  if (!GetRandom(kAesKeySize, &key)) {
    return false;
  }
  if (!EncryptWithSeed(KeyDerivationScheme::kNone, data, key, encrypted_data)) {
    return false;
  }
  if (!WrapKeyOAEP(key, rsa.get(), key_id, encrypted_data)) {
    encrypted_data->Clear();
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::AesEncrypt(const EVP_CIPHER* cipher,
                                   const std::string& data,
                                   const std::string& key,
                                   const std::string& iv,
                                   std::string* encrypted_data) {
  if (key.size() != static_cast<size_t>(EVP_CIPHER_key_length(cipher)) ||
      iv.size() != kAesBlockSize) {
    return false;
  }
  if (data.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    // EVP_EncryptUpdate takes a signed int.
    return false;
  }
  std::string mutable_data(data);
  unsigned char* input_buffer = StringAsOpenSSLBuffer(&mutable_data);
  std::string mutable_key(key);
  unsigned char* key_buffer = StringAsOpenSSLBuffer(&mutable_key);
  std::string mutable_iv(iv);
  unsigned char* iv_buffer = StringAsOpenSSLBuffer(&mutable_iv);
  // Allocate enough space for the output (including padding).
  encrypted_data->resize(data.size() + kAesBlockSize);
  auto output_buffer =
      reinterpret_cast<unsigned char*>(std::data(*encrypted_data));
  int output_size = 0;
  crypto::ScopedEVP_CIPHER_CTX encryption_context(EVP_CIPHER_CTX_new());
  if (!encryption_context) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  if (!EVP_EncryptInit_ex(encryption_context.get(), cipher, nullptr, key_buffer,
                          iv_buffer)) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  if (!EVP_EncryptUpdate(encryption_context.get(), output_buffer, &output_size,
                         input_buffer, data.size())) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  size_t total_size = output_size;
  output_buffer += output_size;
  output_size = 0;
  if (!EVP_EncryptFinal_ex(encryption_context.get(), output_buffer,
                           &output_size)) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  total_size += output_size;
  encrypted_data->resize(total_size);
  return true;
}

bool CryptoUtilityImpl::AesDecrypt(const EVP_CIPHER* cipher,
                                   const std::string& encrypted_data,
                                   const std::string& key,
                                   const std::string& iv,
                                   std::string* data) {
  if (key.size() != static_cast<size_t>(EVP_CIPHER_key_length(cipher)) ||
      iv.size() != kAesBlockSize) {
    return false;
  }
  if (encrypted_data.size() >
      static_cast<size_t>(std::numeric_limits<int>::max())) {
    // EVP_DecryptUpdate takes a signed int.
    return false;
  }
  std::string mutable_encrypted_data(encrypted_data);
  unsigned char* input_buffer = StringAsOpenSSLBuffer(&mutable_encrypted_data);
  std::string mutable_key(key);
  unsigned char* key_buffer = StringAsOpenSSLBuffer(&mutable_key);
  std::string mutable_iv(iv);
  unsigned char* iv_buffer = StringAsOpenSSLBuffer(&mutable_iv);
  // Allocate enough space for the output.
  data->resize(encrypted_data.size());
  unsigned char* output_buffer = StringAsOpenSSLBuffer(data);
  int output_size = 0;
  crypto::ScopedEVP_CIPHER_CTX decryption_context(EVP_CIPHER_CTX_new());
  if (!decryption_context) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  if (!EVP_DecryptInit_ex(decryption_context.get(), cipher, nullptr, key_buffer,
                          iv_buffer)) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  if (!EVP_DecryptUpdate(decryption_context.get(), output_buffer, &output_size,
                         input_buffer, encrypted_data.size())) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  size_t total_size = output_size;
  output_buffer += output_size;
  output_size = 0;
  if (!EVP_DecryptFinal_ex(decryption_context.get(), output_buffer,
                           &output_size)) {
    LOG(ERROR) << __func__ << ": " << GetOpenSSLError();
    return false;
  }
  total_size += output_size;
  data->resize(total_size);
  return true;
}

std::string CryptoUtilityImpl::HmacSha256(const std::string& key,
                                          const std::string& data) {
  unsigned char mac[SHA256_DIGEST_LENGTH];
  std::string mutable_data(data);
  unsigned char* data_buffer = StringAsOpenSSLBuffer(&mutable_data);
  HMAC(EVP_sha256(), key.data(), key.size(), data_buffer, data.size(), mac,
       nullptr);
  return std::string(std::begin(mac), std::end(mac));
}

std::string CryptoUtilityImpl::HmacSha512(const std::string& key,
                                          const std::string& data) {
  unsigned char mac[SHA512_DIGEST_LENGTH];
  std::string mutable_data(data);
  unsigned char* data_buffer = StringAsOpenSSLBuffer(&mutable_data);
  HMAC(EVP_sha512(), key.data(), key.size(), data_buffer, data.size(), mac,
       nullptr);
  return std::string(std::begin(mac), std::end(mac));
}

int CryptoUtilityImpl::DefaultDigestAlgoForSignature() {
  switch (tpm_utility_->GetVersion()) {
    case attestation::TPM_2_0:
      return NID_sha256;
    case attestation::TPM_1_2:
      return NID_sha1;
  }
}

bool CryptoUtilityImpl::TssCompatibleEncrypt(const std::string& input,
                                             const std::string& key,
                                             std::string* output) {
  CHECK(output);
  CHECK_EQ(key.size(), kAesKeySize);
  std::string iv;
  if (!GetRandom(kAesBlockSize, &iv)) {
    LOG(ERROR) << __func__ << ": GetRandom failed.";
    return false;
  }
  std::string encrypted;
  if (!AesEncrypt(EVP_aes_256_cbc(), input, key, iv, &encrypted)) {
    LOG(ERROR) << __func__ << ": Encryption failed.";
    return false;
  }
  *output = iv + encrypted;
  return true;
}

bool CryptoUtilityImpl::TpmCompatibleOAEPEncrypt(const std::string& input,
                                                 RSA* key,
                                                 std::string* output) {
  CHECK(output);
  // The custom OAEP parameter as specified in TPM Main Part 1, Section 31.1.1.
  return OAEPEncryptWithLabel("TCPA", input, key, EVP_sha1(), EVP_sha1(),
                              output);
}

bool CryptoUtilityImpl::EncryptWithSeed(KeyDerivationScheme derivation_scheme,
                                        const std::string& input,
                                        const std::string& seed,
                                        EncryptedData* encrypted) {
  std::string iv;
  if (!GetRandom(kAesBlockSize, &iv)) {
    return false;
  }
  std::string aes_key;
  std::string hmac_key;
  if (derivation_scheme == KeyDerivationScheme::kNone) {
    aes_key = hmac_key = seed;
  } else if (derivation_scheme == KeyDerivationScheme::kHashWithHeaders) {
    aes_key = crypto::SHA256HashString(kHashHeaderForEncrypt + seed);
    hmac_key = crypto::SHA256HashString(kHashHeaderForMac + seed);
  }
  std::string encrypted_data;
  if (!AesEncrypt(EVP_aes_256_cbc(), input, aes_key, iv, &encrypted_data)) {
    return false;
  }
  encrypted->set_encrypted_data(encrypted_data);
  encrypted->set_iv(iv);
  encrypted->set_mac(HmacSha512(hmac_key, iv + encrypted_data));
  return true;
}

bool CryptoUtilityImpl::DecryptWithSeed(KeyDerivationScheme derivation_scheme,
                                        const EncryptedData& input,
                                        const std::string& seed,
                                        std::string* decrypted) {
  std::string aes_key;
  std::string hmac_key;
  if (derivation_scheme == KeyDerivationScheme::kNone) {
    aes_key = hmac_key = seed;
  } else if (derivation_scheme == KeyDerivationScheme::kHashWithHeaders) {
    aes_key = crypto::SHA256HashString(kHashHeaderForEncrypt + seed);
    hmac_key = crypto::SHA256HashString(kHashHeaderForMac + seed);
  }
  std::string expected_mac =
      HmacSha512(hmac_key, input.iv() + input.encrypted_data());
  if (expected_mac.length() != input.mac().length()) {
    LOG(ERROR) << __func__ << ": MAC length mismatch.";
    return false;
  }
  if (!crypto::SecureMemEqual(expected_mac.data(), input.mac().data(),
                              expected_mac.length())) {
    LOG(ERROR) << __func__ << ": MAC mismatch.";
    return false;
  }
  if (!AesDecrypt(EVP_aes_256_cbc(), input.encrypted_data(), aes_key,
                  input.iv(), decrypted)) {
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::WrapKeyOAEP(const std::string& key,
                                    RSA* wrapping_key,
                                    const std::string& wrapping_key_id,
                                    EncryptedData* output) {
  const unsigned char* key_buffer = StringAsConstOpenSSLBuffer(key);
  std::string encrypted_key;
  encrypted_key.resize(RSA_size(wrapping_key));
  unsigned char* encrypted_key_buffer = StringAsOpenSSLBuffer(&encrypted_key);
  int length = RSA_public_encrypt(key.size(), key_buffer, encrypted_key_buffer,
                                  wrapping_key, RSA_PKCS1_OAEP_PADDING);
  if (length == -1) {
    LOG(ERROR) << "RSA_public_encrypt failed.";
    return false;
  }
  encrypted_key.resize(length);
  output->set_wrapped_key(encrypted_key);
  output->set_wrapping_key_id(wrapping_key_id);
  return true;
}

std::string CryptoUtilityImpl::GetTpm2KeyNameFromPublicKey(
    const std::string& public_key_tpm_format) {
  // TPM_ALG_SHA256 = 0x000B, here in big-endian order.
  std::string prefix("\x00\x0B", 2);
  return prefix + crypto::SHA256HashString(public_key_tpm_format);
}

std::string CryptoUtilityImpl::Tpm2CompatibleKDFa(const std::string& key,
                                                  const std::string& label,
                                                  const std::string& context,
                                                  int bits) {
  // Due to the assumptions of SHA256 and a 128/256-bit output, we can simplify
  // to just one iteration.
  if (bits != 128 && bits != 256) {
    LOG(ERROR) << __func__ << ": Unsupported key size: " << bits;
    return std::string("");
  }
  std::string iteration("\x00\x00\x00\x01", 4);  // Big-endian 32-bit 1.
  std::string null_separator("\x00", 1);
  // Encode number of bits as big-endian 32-bit value (128 or 256).
  std::string b_buf(bits == 128 ? "\x00\x00\x00\x80" : "\x00\x00\x01\x00", 4);
  return HmacSha256(key, iteration + label + null_separator + context + b_buf)
      .substr(0, bits / 8);
}

bool CryptoUtilityImpl::Tpm2CompatibleOAEPEncrypt(const std::string& label,
                                                  const std::string& input,
                                                  RSA* key,
                                                  std::string* output) {
  std::string zero_terminated_label = label + std::string(1, '\x00');
  return OAEPEncryptWithLabel(zero_terminated_label, input, key, EVP_sha256(),
                              EVP_sha256(), output);
}

bool CryptoUtilityImpl::OAEPEncryptWithLabel(const std::string& label,
                                             const std::string& input,
                                             RSA* key,
                                             const EVP_MD* md,
                                             const EVP_MD* mgf1md,
                                             std::string* output) {
  std::string padded_input;
  padded_input.resize(RSA_size(key));
  auto padded_buffer =
      reinterpret_cast<unsigned char*>(std::data(padded_input));
  auto input_buffer = reinterpret_cast<const unsigned char*>(input.data());
  auto label_buffer = reinterpret_cast<const unsigned char*>(label.data());
  int result = RSA_padding_add_PKCS1_OAEP_mgf1(
      padded_buffer, padded_input.size(), input_buffer, input.size(),
      label_buffer, label.size(), md, mgf1md);
  if (!result) {
    LOG(ERROR) << __func__
               << ": Failed to add OAEP padding: " << GetOpenSSLError();
    return false;
  }
  output->resize(padded_input.size());
  auto output_buffer = reinterpret_cast<unsigned char*>(std::data(*output));
  result = RSA_public_encrypt(padded_input.size(), padded_buffer, output_buffer,
                              key, RSA_NO_PADDING);
  if (result == -1) {
    LOG(ERROR) << __func__ << ": Failed to encrypt OAEP padded input: "
               << GetOpenSSLError();
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::CreateSPKAC(const std::string& key_blob,
                                    const std::string& public_key,
                                    KeyType key_type,
                                    std::string* spkac) {
  // Get the certified public key as an EVP_PKEY.
  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(public_key.data());
  crypto::ScopedEVP_PKEY evp_pkey(EVP_PKEY_new());
  if (!evp_pkey.get()) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_new: " << GetOpenSSLError();
    return false;
  }
  if (key_type == KEY_TYPE_RSA) {
    crypto::ScopedRSA rsa(
        d2i_RSAPublicKey(nullptr, &asn1_ptr, public_key.size()));
    if (!rsa.get()) {
      LOG(ERROR) << __func__
                 << ": Failed to decode public key: " << GetOpenSSLError();
      return false;
    }
    if (!EVP_PKEY_set1_RSA(evp_pkey.get(), rsa.get())) {
      LOG(ERROR) << __func__
                 << ": Failed to call EVP_PKEY_set1_RSA: " << GetOpenSSLError();
      return false;
    }
  } else if (key_type == KEY_TYPE_ECC) {
    crypto::ScopedEC_KEY ec_key(
        d2i_EC_PUBKEY(nullptr, &asn1_ptr, public_key.size()));
    if (!ec_key.get()) {
      LOG(ERROR) << __func__
                 << ": Failed to decode ECC public key: " << GetOpenSSLError();
      return false;
    }
    if (EVP_PKEY_set1_EC_KEY(evp_pkey.get(), ec_key.get()) != 1) {
      LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_set1_EC_KEY: "
                 << GetOpenSSLError();
      return false;
    }
  } else {
    LOG(DFATAL) << __func__ << ": Unrecognized key type.";
    return false;
  }

  return CreateSPKACInternal(key_blob, evp_pkey, spkac);
}

bool CryptoUtilityImpl::CreateSPKACInternal(
    const std::string& key_blob,
    const crypto::ScopedEVP_PKEY& public_key,
    std::string* spkac) {
  CHECK(public_key.get());
  // Fill in the public key.
  crypto::ScopedOpenSSL<NETSCAPE_SPKI, NETSCAPE_SPKI_free> spki(
      NETSCAPE_SPKI_new());
  if (!spki.get()) {
    LOG(ERROR) << __func__ << ": Failed to create SPKI.";
    return false;
  }
  if (!NETSCAPE_SPKI_set_pubkey(spki.get(), public_key.get())) {
    LOG(ERROR) << __func__ << ": Failed to set pubkey for SPKI.";
    return false;
  }

  // Fill in a random challenge.
  std::string challenge;
  size_t challenge_size = (tpm_utility_->GetVersion() == TPM_1_2)
                              ? base::kSHA1Length
                              : crypto::kSHA256Length;
  if (!GetRandom(challenge_size, &challenge)) {
    LOG(ERROR) << __func__ << ": Failed to GetRandom(challenge).";
    return false;
  }
  std::string challenge_hex =
      base::HexEncode(challenge.data(), challenge.size());
  if (!ASN1_STRING_set(spki.get()->spkac->challenge, challenge_hex.data(),
                       challenge_hex.size())) {
    LOG(ERROR) << __func__ << ": Failed to set challenge in SPKAC.";
    return false;
  }

  // Generate the signature.
  unsigned char* buffer = NULL;
  int length = i2d_NETSCAPE_SPKAC(spki.get()->spkac, &buffer);
  if (length <= 0) {
    LOG(ERROR) << __func__ << ": Failed to get SPKAC.";
    return false;
  }
  std::string data_to_sign(reinterpret_cast<char*>(buffer), length);
  OPENSSL_free(buffer);
  std::string signature;
  if (!tpm_utility_->Sign(key_blob, data_to_sign, &signature)) {
    LOG(ERROR) << __func__ << ": Failed to sign SPKAC.";
    return false;
  }

  // Fill in the signature and algorithm.
  if (!ASN1_BIT_STRING_set(
          spki.get()->signature,
          reinterpret_cast<unsigned char*>(const_cast<char*>(signature.data())),
          signature.size())) {
    LOG(ERROR) << __func__ << ": Failed to set signature in SPKAC.";
    return false;
  }
  // Be explicit that there are zero unused bits; otherwise i2d below will
  // automatically detect unused bits but signatures require zero unused bits.
  spki.get()->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  X509_ALGOR* sig_algor = spki.get()->sig_algor;
#else
  X509_ALGOR* sig_algor = &spki.get()->sig_algor;
#endif
  const int sig_algo_nid = EVP_PKEY_base_id(public_key.get()) == EVP_PKEY_RSA
                               ? NID_sha256WithRSAEncryption
                               : NID_ecdsa_with_SHA256;
  X509_ALGOR_set0(sig_algor, OBJ_nid2obj(sig_algo_nid), V_ASN1_NULL, NULL);

  // DER encode.
  buffer = NULL;
  length = i2d_NETSCAPE_SPKI(spki.get(), &buffer);
  if (length <= 0) {
    LOG(ERROR) << __func__ << ": Failed to get SPKI.";
    return false;
  }
  spkac->assign(reinterpret_cast<char*>(buffer), length);
  OPENSSL_free(buffer);

  return true;
}

bool CryptoUtilityImpl::VerifyCertificate(
    const std::string& certificate, const std::string& ca_public_key_hex) {
  crypto::ScopedRSA rsa = CreateRSAFromHexModulus(ca_public_key_hex);
  if (!rsa.get()) {
    LOG(ERROR) << __func__ << ": Failed to decode CA public key.";
    return false;
  }
  crypto::ScopedEVP_PKEY issuer_key(EVP_PKEY_new());
  if (!issuer_key.get()) {
    LOG(ERROR) << __func__ << ": Failed to create EVP PKEY.";
    return false;
  }
  EVP_PKEY_assign_RSA(issuer_key.get(), rsa.release());
  auto x509 = CreateX509FromCertificate(certificate);
  if (!x509.get()) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }
  if (X509_verify(x509.get(), issuer_key.get()) != 1) {
    LOG(ERROR) << __func__
               << ": Bad certificate signature: " << GetOpenSSLError();
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::VerifyCertificateWithSubjectPublicKey(
    const std::string& certificate, const std::string& ca_public_key_der_hex) {
  std::vector<uint8_t> ca_public_key_der_vec;
  if (!base::HexStringToBytes(ca_public_key_der_hex, &ca_public_key_der_vec)) {
    LOG(ERROR) << __func__ << "Failed to hex-decode subject public key info.";
    return false;
  }
  std::string ca_public_key_der(ca_public_key_der_vec.begin(),
                                ca_public_key_der_vec.end());

  auto openssl_buffer = StringAsConstOpenSSLBuffer(ca_public_key_der);
  crypto::ScopedEVP_PKEY issuer_key(
      d2i_PUBKEY(nullptr, &openssl_buffer, ca_public_key_der.size()));
  if (!issuer_key) {
    LOG(ERROR) << __func__
               << ": Failed to decode CA public key: " << GetOpenSSLError();
    return false;
  }
  auto x509 = CreateX509FromCertificate(certificate);
  if (!x509) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }
  if (X509_verify(x509.get(), issuer_key.get()) != 1) {
    LOG(ERROR) << __func__
               << ": Bad certificate signature: " << GetOpenSSLError();
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::GetCertificateSubjectPublicKeyInfo(
    const std::string& certificate, std::string* public_key) {
  // Some TPM 1.2 certificates use OAEP key type (rsaOAEP (PKCS #1)). It is not
  // supported algorithm in OpenSSL, so we can't parse the public key data to
  // public key object.
  //
  // At here, we only decode X509 format and store raw byte string
  // (ASN1_BIT_STRING) of SubjectPublicKeyInfo to x509->cert_info->key, such
  // that we can safely pass this i2d_X509_PUBKEY, since it directly output raw
  // byte string. But we can't pass it some utility which attempt to parse it
  // such like X509_PUBKEY_get().
  auto x509 = CreateX509FromCertificate(certificate);
  if (!x509.get()) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }

  unsigned char* pubkey_buffer = nullptr;
  int length =
      i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509.get()), &pubkey_buffer);
  if (length < 0) {
    LOG(ERROR) << __func__
               << ": Failed to dump SubjectPublicKeyInfo from cert.";
    return false;
  }
  crypto::ScopedOpenSSLBytes scoped_pubkey_buffer(pubkey_buffer);
  public_key->assign(reinterpret_cast<char*>(pubkey_buffer), length);
  return true;
}

bool CryptoUtilityImpl::GetCertificatePublicKey(const std::string& certificate,
                                                std::string* public_key) {
  auto x509 = CreateX509FromCertificate(certificate);
  if (!x509.get()) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }
  crypto::ScopedEVP_PKEY pkey(X509_get_pubkey(x509.get()));
  if (!pkey) {
    LOG(ERROR) << __func__ << ": Failed to get EVP_PKEY from the certificate: "
               << GetOpenSSLError();
    return false;
  }
  crypto::ScopedRSA rsa(EVP_PKEY_get1_RSA(pkey.get()));
  if (!rsa) {
    LOG(ERROR) << __func__
               << ": Failed to get RSA from EVP_PKEY: " << GetOpenSSLError();
    return false;
  }
  int der_length = i2d_RSAPublicKey(rsa.get(), nullptr);
  if (der_length < 0) {
    LOG(ERROR) << __func__
               << ": Bad length of der-encoded output: " << GetOpenSSLError();
    return false;
  }
  public_key->resize(der_length);
  unsigned char* der_buffer =
      reinterpret_cast<unsigned char*>(std::data(*public_key));
  if (i2d_RSAPublicKey(rsa.get(), &der_buffer) < 0) {
    LOG(ERROR) << __func__
               << ": Bad length of der-encoded output: " << GetOpenSSLError();
    return false;
  }
  return true;
}

bool CryptoUtilityImpl::GetCertificateIssuerName(const std::string& certificate,
                                                 std::string* issuer_name) {
  auto x509 = CreateX509FromCertificate(certificate);
  if (!x509.get()) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }
  char issuer_buf[100];  // A longer CN will truncate.
  X509_NAME* x509_name = X509_get_issuer_name(x509.get());

  if (X509_NAME_get_text_by_NID(x509_name, NID_commonName, issuer_buf,
                                std::size(issuer_buf)) == -1) {
    LOG(WARNING) << __func__ << ": Failed to get the issuer name text by NID";

    // A workaround for misconfigured certificate issuer field found in early
    // samples of the Dauntless chip.
    //
    // Retrieve the text representation of the issuer name, and, if it matches
    // the misconfigured value, replace it with the expected value, hardcoded
    // to "CROS D2 CIK".
    if (!X509_NAME_oneline(x509_name, issuer_buf, sizeof(issuer_buf))) {
      LOG(ERROR) << __func__ << ": Failed to retrieve alt name";
      return false;
    }

    if (strcmp(issuer_buf,
               "/C=US/ST=California/O=Google Inc./OU=Engineering")) {
      LOG(ERROR) << __func__ << ": Alt name is ^" << issuer_buf << "^";
      return false;
    }

    strncpy(issuer_buf, "CROS D2 CIK", sizeof(issuer_buf));
    LOG(WARNING) << __func__ << ": Substituted issuer name with " << issuer_buf;
  }

  issuer_name->assign(issuer_buf);
  return true;
}

bool CryptoUtilityImpl::GetKeyDigest(const std::string& public_key,
                                     std::string* key_digest) {
  auto asn1_ptr = reinterpret_cast<const unsigned char*>(public_key.data());
  crypto::ScopedRSA rsa(d2i_RSA_PUBKEY(NULL, &asn1_ptr, public_key.size()));
  if (!rsa.get()) {
    LOG(ERROR) << __func__ << ": Failed to decode certified public key.";
    return false;
  }
  std::vector<unsigned char> modulus(RSA_size(rsa.get()));
  const BIGNUM* n;
  RSA_get0_key(rsa.get(), &n, nullptr, nullptr);
  if (BN_bn2bin(n, modulus.data()) != modulus.size()) {
    LOG(ERROR) << __func__ << ": Failed to extract modulus.";
    return false;
  }
  char digest_buf[base::kSHA1Length];
  base::SHA1HashBytes(modulus.data(), modulus.size(),
                      reinterpret_cast<unsigned char*>(digest_buf));
  key_digest->assign(digest_buf, sizeof(digest_buf));
  return true;
}

}  // namespace attestation
