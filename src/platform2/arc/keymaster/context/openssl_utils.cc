// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/openssl_utils.h"

#include <base/check_op.h>
#include <base/stl_util.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <optional>

namespace arc {
namespace keymaster {
namespace context {

namespace {

constexpr size_t kKeySize = 32;
constexpr size_t kAes256GcmPadding = 16;

// Encrypts a given |input| using AES-GCM-256 with |key|, |auth_data|, and |iv|.
// Returns std::nullopt if there's an error in the OpenSSL operation.
std::optional<brillo::Blob> DoAes256GcmEncrypt(
    const brillo::SecureBlob& key,
    const brillo::Blob& auth_data,
    const brillo::Blob& iv,
    const brillo::SecureBlob& input) {
  CHECK_EQ(key.size(), kKeySize);
  CHECK_EQ(iv.size(), kIvSize);
  // Initialize cipher.
  crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                              /* engine */ nullptr,
                              /* key */ key.data(), /* iv */ iv.data())) {
    return std::nullopt;
  }

  // Update operation with |auth_data|, out pointer must be null.
  int auth_update_len;
  if (1 != EVP_EncryptUpdate(ctx.get(), /* out */ nullptr, &auth_update_len,
                             auth_data.data(), auth_data.size())) {
    return std::nullopt;
  }

  // Update operation with |input|.
  int update_len;
  brillo::Blob output(input.size() + kAes256GcmPadding);
  if (1 != EVP_EncryptUpdate(ctx.get(), output.data(), &update_len,
                             input.data(), input.size())) {
    return std::nullopt;
  }

  // Finish operation, accumulate results in |output|.
  int finish_len;
  if (1 !=
      EVP_EncryptFinal_ex(ctx.get(), output.data() + update_len, &finish_len)) {
    return std::nullopt;
  }
  CHECK_GE(output.size(), update_len + finish_len);
  output.resize(update_len + finish_len);

  // Retrieve tag.
  brillo::Blob tag(kTagSize);
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(),
                               tag.data())) {
    return std::nullopt;
  }

  // Append tag to |output| and return the encrypted blob.
  output.insert(output.end(), tag.begin(), tag.end());
  return output;
}

// Decrypts a given |input| using AES-GCM-256 with |key|, |auth_data|, and |iv|.
// Returns std::nullopt if there's an error in the OpenSSL operation.
std::optional<brillo::SecureBlob> DoAes256GcmDecrypt(
    const brillo::SecureBlob& key,
    const brillo::Blob& auth_data,
    const brillo::Blob& iv,
    const brillo::Blob& input) {
  CHECK_EQ(key.size(), kKeySize);
  CHECK_EQ(iv.size(), kIvSize);

  // Input must have a tag appended to it.
  if (input.size() < kTagSize)
    return std::nullopt;

  // Initialize cipher.
  crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                              /* engine */ nullptr, key.data(), iv.data())) {
    return std::nullopt;
  }

  // Set expected tag.
  brillo::Blob tag(input.end() - kTagSize, input.end());
  size_t input_len = input.size() - tag.size();
  if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(),
                               tag.data())) {
    return std::nullopt;
  }

  // Update operation with |auth_data|, out pointer must be null.
  int auth_update_len;
  if (1 != EVP_DecryptUpdate(ctx.get(), /* out */ nullptr, &auth_update_len,
                             auth_data.data(), auth_data.size())) {
    return std::nullopt;
  }

  // Update operation with |input|.
  int update_len;
  brillo::SecureBlob output(input_len + kAes256GcmPadding);
  if (1 != EVP_DecryptUpdate(ctx.get(), output.data(), &update_len,
                             input.data(), input_len)) {
    return std::nullopt;
  }

  // Finish operation, accumulate results in |output|.
  int finish_len;
  if (1 !=
      EVP_CipherFinal_ex(ctx.get(), output.data() + update_len, &finish_len)) {
    return std::nullopt;
  }
  CHECK_GE(output.size(), update_len + finish_len);
  output.resize(update_len + finish_len);

  // Return decrypted blob;
  return output;
}

}  // anonymous namespace

std::optional<brillo::Blob> Aes256GcmEncrypt(const brillo::SecureBlob& key,
                                             const brillo::Blob& auth_data,
                                             const brillo::SecureBlob& input) {
  // Compute a random IV.
  brillo::Blob iv(kIvSize);
  if (1 != RAND_bytes(iv.data(), iv.size()))
    return std::nullopt;

  // Encrypt the input.
  std::optional<brillo::Blob> encrypted =
      DoAes256GcmEncrypt(key, auth_data, iv, input);
  if (!encrypted.has_value())
    return std::nullopt;

  // Append the random IV used for encryption to the output.
  encrypted->insert(encrypted->end(), iv.begin(), iv.end());
  return encrypted;
}

std::optional<brillo::SecureBlob> Aes256GcmDecrypt(
    const brillo::SecureBlob& key,
    const brillo::Blob& auth_data,
    const brillo::Blob& input) {
  // Input must have an IV appended to it.
  if (input.size() < kIvSize)
    return std::nullopt;

  // Split the input between the encrypted portion and the IV.
  brillo::Blob encrypted(input.begin(), input.end() - kIvSize);
  brillo::Blob iv(input.end() - kIvSize, input.end());

  // Decrypt the input.
  return DoAes256GcmDecrypt(key, auth_data, iv, encrypted);
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
