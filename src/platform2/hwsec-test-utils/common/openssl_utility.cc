// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/common/openssl_utility.h"

#include <memory>
#include <optional>

#include <base/check.h>
#include <base/logging.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

namespace hwsec_test_utils {

namespace {

constexpr int kAesBlockSize = 16;

}  // namespace

void InitializeOpenSSL() {
  static bool g_openssl_initialized = false;
  if (g_openssl_initialized) {
    return;
  }
  g_openssl_initialized = true;
  OpenSSL_add_all_algorithms();
  // Some certificates to RSA keys, e.g., endorsement certificates for TPM1.2,
  // could have the algorithm type "rsaesOaep", which is not recognized by
  // OpenSSL directly.
  EVP_PKEY_asn1_add_alias(EVP_PKEY_RSA, NID_rsaesOaep);
  ERR_load_crypto_strings();
}

std::string GetOpenSSLError() {
  crypto::ScopedBIO bio(BIO_new(BIO_s_mem()));
  ERR_print_errors(bio.get());
  char* data = nullptr;
  int data_len = BIO_get_mem_data(bio.get(), &data);
  std::string error_string(data, data_len);
  return error_string;
}

crypto::ScopedEVP_PKEY CreateNewEcKey() {
  crypto::ScopedEC_KEY ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!ec_key) {
    LOG(ERROR) << __func__ << ": Failed to call EC_KEY_new_by_curve_name: "
               << GetOpenSSLError();
    return nullptr;
  }
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
  if (EC_KEY_generate_key(ec_key.get()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EC_KEY_generate_key: " << GetOpenSSLError();
    return nullptr;
  }
  // Not really sure if we need this call; supposedly it does no harm except for
  // neglectable performance overhead.
  if (EC_KEY_check_key(ec_key.get()) != 1) {
    LOG(WARNING) << __func__
                 << ": Retry due to Bad ECC key (EC_KEY_check_key failed): "
                 << GetOpenSSLError();
    // Probabilistically impossible to result in infinite loop; just invoke
    // recursive call.
    return CreateNewEcKey();
  }

  crypto::ScopedEVP_PKEY key(EVP_PKEY_new());
  if (!key) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_new: " << GetOpenSSLError();
    return nullptr;
  }
  if (EVP_PKEY_set1_EC_KEY(key.get(), ec_key.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_set1_EC_KEY: "
               << GetOpenSSLError();
    return nullptr;
  }
  return key;
}

crypto::ScopedEVP_PKEY PemToEVP(const std::string& pem) {
  crypto::ScopedBIO bio(
      BIO_new_mem_buf(const_cast<char*>(pem.data()), pem.size()));
  if (!bio) {
    LOG(ERROR) << __func__
               << ": Failed to create mem BIO: " << GetOpenSSLError();
    return nullptr;
  }
  crypto::ScopedEVP_PKEY key(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    LOG(ERROR) << __func__
               << ": Failed to read key with PEM_read_bio_PrivateKey: "
               << GetOpenSSLError();
    return nullptr;
  }
  return key;
}

crypto::ScopedX509 PemToX509(const std::string& pem) {
  crypto::ScopedBIO bio(
      BIO_new_mem_buf(const_cast<char*>(pem.data()), pem.size()));
  if (!bio) {
    LOG(ERROR) << __func__
               << ": Failed to create mem BIO: " << GetOpenSSLError();
    return nullptr;
  }
  crypto::ScopedX509 x509(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!x509) {
    LOG(ERROR) << __func__
               << ": Failed to call PEM_read_bio_X509: " << GetOpenSSLError();
    return nullptr;
  }
  return x509;
}

std::optional<std::string> GetRandom(size_t length) {
  std::unique_ptr<unsigned char[]> buffer =
      std::make_unique<unsigned char[]>(length);
  if (RAND_bytes(buffer.get(), length) != 1) {
    return {};
  }
  return std::string(buffer.get(), buffer.get() + length);
}

std::optional<std::string> EVPDigestSign(const crypto::ScopedEVP_PKEY& key,
                                         const EVP_MD* md_type,
                                         const std::string& data) {
  CHECK(key.get());
  CHECK(md_type != nullptr);

  crypto::ScopedEVP_MD_CTX mdctx(EVP_MD_CTX_new());
  if (!mdctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_MD_CTX: " << GetOpenSSLError();
    return {};
  }

  if (EVP_DigestSignInit(mdctx.get(), nullptr, md_type, nullptr, key.get()) !=
      1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_DigestSignInit: " << GetOpenSSLError();
    return {};
  }
  if (EVP_DigestSignUpdate(mdctx.get(), data.data(), data.length()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_DigestSignUpdate: "
               << GetOpenSSLError();
    return {};
  }
  size_t output_length = 0;
  if (EVP_DigestSignFinal(mdctx.get(), nullptr, &output_length) != 1) {
    LOG(ERROR)
        << __func__
        << ": Failed to call EVP_DigestSignFinal to get signature length: "
        << GetOpenSSLError();
    return {};
  }
  std::unique_ptr<unsigned char[]> output =
      std::make_unique<unsigned char[]>(output_length);
  if (EVP_DigestSignFinal(mdctx.get(), output.get(), &output_length) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_DigestVerifyFinal: "
               << GetOpenSSLError();
    return {};
  }
  return std::string(output.get(), output.get() + output_length);
}

bool EVPDigestVerify(const crypto::ScopedEVP_PKEY& key,
                     const EVP_MD* md_type,
                     const std::string& data,
                     const std::string& signature) {
  CHECK(key.get());
  CHECK(md_type != nullptr);

  crypto::ScopedEVP_MD_CTX mdctx(EVP_MD_CTX_new());
  if (!mdctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_MD_CTX: " << GetOpenSSLError();
    return false;
  }

  if (EVP_DigestVerifyInit(mdctx.get(), nullptr, md_type, nullptr, key.get()) !=
      1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_DigestVerifyInit: "
               << GetOpenSSLError();
    return false;
  }
  if (EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.length()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_DigestVerifyUpdate: "
               << GetOpenSSLError();
    return false;
  }

  if (EVP_DigestVerifyFinal(
          mdctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
          signature.length()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_DigestVerifyFinal: "
               << GetOpenSSLError();
    return false;
  }
  return true;
}

std::optional<std::string> EVPRsaEncrypt(const crypto::ScopedEVP_PKEY& key,
                                         const std::string& data,
                                         int rsa_padding) {
  crypto::ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
  if (!ctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_PKEY_CTX: " << GetOpenSSLError();
    return {};
  }
  if (EVP_PKEY_encrypt_init(ctx.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_decrypt_init: "
               << GetOpenSSLError();
    return {};
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), rsa_padding) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_CTX_set_rsa_padding: "
               << GetOpenSSLError();
    return {};
  }
  size_t output_length = 0;
  if (EVP_PKEY_encrypt(ctx.get(), nullptr, &output_length,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.length()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_encrypt to get output length: "
               << GetOpenSSLError();
    return {};
  }
  std::unique_ptr<unsigned char[]> output =
      std::make_unique<unsigned char[]>(output_length);
  if (EVP_PKEY_encrypt(ctx.get(), output.get(), &output_length,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.length()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_encrypt: " << GetOpenSSLError();
    return {};
  }
  return std::string(output.get(), output.get() + output_length);
}

std::optional<std::string> EVPRsaDecrypt(const crypto::ScopedEVP_PKEY& key,
                                         const std::string& encrypted_data,
                                         int rsa_padding) {
  crypto::ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
  if (!ctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_PKEY_CTX: " << GetOpenSSLError();
    return {};
  }
  if (EVP_PKEY_decrypt_init(ctx.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_decrypt_init: "
               << GetOpenSSLError();
    return {};
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), rsa_padding) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_CTX_set_rsa_padding: "
               << GetOpenSSLError();
    return {};
  }
  size_t output_length = 0;
  if (EVP_PKEY_decrypt(
          ctx.get(), nullptr, &output_length,
          reinterpret_cast<const unsigned char*>(encrypted_data.data()),
          encrypted_data.length()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_decrypt to get output length: "
               << GetOpenSSLError();
    return {};
  }
  std::unique_ptr<unsigned char[]> output =
      std::make_unique<unsigned char[]>(output_length);
  if (EVP_PKEY_decrypt(
          ctx.get(), output.get(), &output_length,
          reinterpret_cast<const unsigned char*>(encrypted_data.data()),
          encrypted_data.length()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_decrypt: " << GetOpenSSLError();
    return {};
  }
  return std::string(output.get(), output.get() + output_length);
}

std::optional<std::string> EVPAesEncrypt(const std::string& data,
                                         const EVP_CIPHER* evp_cipher,
                                         const std::string& aes_key,
                                         const std::string& iv) {
  crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_CIPHER_CTX: " << GetOpenSSLError();
    return {};
  }
  if (EVP_EncryptInit_ex(ctx.get(), evp_cipher, /*engine=*/nullptr,
                         reinterpret_cast<const unsigned char*>(aes_key.data()),
                         reinterpret_cast<const unsigned char*>(iv.data())) !=
      1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_DecryptInit_ex: " << GetOpenSSLError();
    return {};
  }
  // Allocate the generous buffer and resize at the end.
  std::unique_ptr<unsigned char[]> output =
      std::make_unique<unsigned char[]>(data.size() + kAesBlockSize);
  int output_length = 0;
  if (EVP_EncryptUpdate(ctx.get(), output.get(), &output_length,
                        reinterpret_cast<const unsigned char*>(data.data()),
                        data.length()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_EncryptUpdate: " << GetOpenSSLError();
    return {};
  }
  int extra_output_length = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), output.get() + output_length,
                          &extra_output_length) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_EncryptFinal_ex: " << GetOpenSSLError();
    return {};
  }
  output_length += extra_output_length;
  return std::string(output.get(), output.get() + output_length);
}

std::optional<std::string> EVPAesDecrypt(const std::string& encrypted_data,
                                         const EVP_CIPHER* evp_cipher,
                                         const std::string& aes_key,
                                         const std::string& iv) {
  crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    LOG(ERROR) << __func__
               << ": Failed to allocate EVP_CIPHER_CTX: " << GetOpenSSLError();
    return {};
  }
  if (EVP_DecryptInit_ex(ctx.get(), evp_cipher, nullptr,
                         reinterpret_cast<const unsigned char*>(aes_key.data()),
                         reinterpret_cast<const unsigned char*>(iv.data())) !=
      1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_DecryptInit_ex: " << GetOpenSSLError();
    return {};
  }
  // The decrypted data is shorter than the encrypted data; allocate the
  // generous buffer and resize at the end.
  std::unique_ptr<unsigned char[]> output =
      std::make_unique<unsigned char[]>(encrypted_data.size());
  int output_length = 0;
  if (EVP_DecryptUpdate(
          ctx.get(), output.get(), &output_length,
          reinterpret_cast<const unsigned char*>(encrypted_data.data()),
          encrypted_data.length()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_DecryptUpdate: " << GetOpenSSLError();
    return {};
  }
  int extra_output_length = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), output.get() + output_length,
                          &extra_output_length) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_DecryptFinal_ex: " << GetOpenSSLError();
    return {};
  }
  output_length += extra_output_length;
  return std::string(output.get(), output.get() + output_length);
}

std::optional<std::string> EVPDerive(const crypto::ScopedEVP_PKEY& key,
                                     const crypto::ScopedEVP_PKEY& peer_key) {
  crypto::ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
  if (!ctx) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_CTX_new: " << GetOpenSSLError();
    return {};
  }
  if (EVP_PKEY_derive_init(ctx.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_derive_init: "
               << GetOpenSSLError();
    return {};
  }
  if (EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_derive_set_peer: "
               << GetOpenSSLError();
    return {};
  }
  size_t output_length = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &output_length) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_derive to get output size: "
               << GetOpenSSLError();
    return {};
  }
  std::unique_ptr<unsigned char[]> output =
      std::make_unique<unsigned char[]>(output_length);
  if (EVP_PKEY_derive(ctx.get(), output.get(), &output_length) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call EVP_PKEY_derive: " << GetOpenSSLError();
    return {};
  }
  return std::string(output.get(), output.get() + output_length);
}

}  // namespace hwsec_test_utils
