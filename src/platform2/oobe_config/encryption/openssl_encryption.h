// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_ENCRYPTION_OPENSSL_ENCRYPTION_H_
#define OOBE_CONFIG_ENCRYPTION_OPENSSL_ENCRYPTION_H_

#include <optional>

#include <brillo/secure_blob.h>

namespace oobe_config {

inline constexpr int kOpenSslEncryptionIvSize = 12;
inline constexpr int kOpenSslEncryptionKeySize = 32;
inline constexpr int kOpenSslEncryptionTagSize = 16;

struct EncryptedData {
  brillo::Blob data;
  brillo::SecureBlob key;
};

// Encrypts data with AES_256_GCM and the provided key and iv. If the key or
// iv are not provided, uses a randomly generated values. Returns the key used
// and the encrypted data on success and `std::nullopt` on failure.
std::optional<EncryptedData> Encrypt(
    const brillo::SecureBlob& plain_dataconst,
    std::optional<brillo::SecureBlob> key = std::nullopt,
    std::optional<brillo::Blob> iv = std::nullopt);

// Decrypts data with AES_256_GCM with the given key. Returns `std::nullopt`
// on failure and the decrypted data on success.
std::optional<brillo::SecureBlob> Decrypt(const EncryptedData& encrypted_data);

}  // namespace oobe_config

#endif  // OOBE_CONFIG_ENCRYPTION_OPENSSL_ENCRYPTION_H_
