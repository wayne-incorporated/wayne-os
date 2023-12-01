// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/encryption/openssl_encryption.h"

#include <optional>
#include <string>

#include <base/strings/strcat.h>
#include <brillo/secure_blob.h>
#include <openssl/rand.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/evp.h>

namespace oobe_config {

namespace {

std::optional<brillo::SecureBlob> GenerateRandomKey() {
  brillo::SecureBlob key(kOpenSslEncryptionKeySize);
  if (!RAND_bytes(key.data(), kOpenSslEncryptionKeySize)) {
    return std::nullopt;
  }
  return key;
}

// Generates a random initialization vector.
std::optional<brillo::Blob> GenerateRandomIV() {
  brillo::Blob iv(kOpenSslEncryptionIvSize);
  if (!RAND_bytes(iv.data(), kOpenSslEncryptionIvSize)) {
    return std::nullopt;
  }
  return iv;
}

}  // namespace

std::optional<EncryptedData> Encrypt(const brillo::SecureBlob& data,
                                     std::optional<brillo::SecureBlob> key,
                                     std::optional<brillo::Blob> iv) {
  if (!key.has_value()) {
    key = GenerateRandomKey();
  }
  if (!iv.has_value()) {
    iv = GenerateRandomIV();
  }

  if (!iv.has_value() || !key.has_value()) {
    return std::nullopt;
  }

  DCHECK_EQ(iv->size(), kOpenSslEncryptionIvSize);
  DCHECK_EQ(key->size(), kOpenSslEncryptionKeySize);

  crypto::ScopedEVP_CIPHER_CTX context(EVP_CIPHER_CTX_new());
  if (!EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
                          key->data(), iv->data())) {
    return std::nullopt;
  }

  brillo::Blob encrypted(data.size());
  int encrypted_length = 0;
  if (!EVP_EncryptUpdate(context.get(), encrypted.data(), &encrypted_length,
                         data.data(), data.size())) {
    return std::nullopt;
  }

  DCHECK_EQ(encrypted_length, data.size());

  if (!EVP_EncryptFinal_ex(context.get(), nullptr, &encrypted_length)) {
    return std::nullopt;
  }

  DCHECK_EQ(encrypted_length, 0);

  brillo::Blob tag(kOpenSslEncryptionTagSize);
  if (!EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                           kOpenSslEncryptionTagSize, tag.data())) {
    return std::nullopt;
  }

  encrypted.insert(encrypted.end(), tag.begin(), tag.end());
  encrypted.insert(encrypted.end(), iv->begin(), iv->end());
  return {{encrypted, *key}};
}

std::optional<brillo::SecureBlob> Decrypt(const EncryptedData& encrypted_data) {
  const brillo::Blob& input = encrypted_data.data;

  CHECK_GE(input.size(), kOpenSslEncryptionTagSize + kOpenSslEncryptionIvSize);
  CHECK_EQ(encrypted_data.key.size(), kOpenSslEncryptionKeySize);

  brillo::Blob encrypted(
      input.begin(),
      input.end() - kOpenSslEncryptionTagSize - kOpenSslEncryptionIvSize);
  brillo::Blob tag(input.begin() + encrypted.size(),
                   input.end() - kOpenSslEncryptionIvSize);
  brillo::Blob iv(input.begin() + encrypted.size() + kOpenSslEncryptionTagSize,
                  input.end());

  crypto::ScopedEVP_CIPHER_CTX context(EVP_CIPHER_CTX_new());

  if (!EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
                          encrypted_data.key.data(), iv.data())) {
    return std::nullopt;
  }

  brillo::SecureBlob output(encrypted.size());
  int output_length;
  if (!EVP_DecryptUpdate(context.get(), output.data(), &output_length,
                         encrypted.data(), encrypted.size())) {
    return std::nullopt;
  }

  DCHECK_EQ(output_length, output.size());

  if (!EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, tag.size(),
                           tag.data())) {
    return std::nullopt;
  }

  if (!EVP_DecryptFinal_ex(context.get(), nullptr, &output_length)) {
    return std::nullopt;
  }

  DCHECK_EQ(output_length, 0);

  return output;
}

}  // namespace oobe_config
