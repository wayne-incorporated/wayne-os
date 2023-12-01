// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONTEXT_OPENSSL_UTILS_H_
#define ARC_KEYMASTER_CONTEXT_OPENSSL_UTILS_H_

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <optional>

// Exposes OpenSSL functionality through an API that is relevant to the ARC
// Keymaster context.

namespace arc {
namespace keymaster {
namespace context {

// Accessible from tests.
constexpr size_t kIvSize = 12;
constexpr size_t kTagSize = 16;

// Authenticated encryption of |input| using AES-GCM-256 with |key| and
// |auth_data|.
//
// A 12-byte IV is randomly generated at every call and appended to the
// encrypted output.
//
// Returns std::nullopt if there's an error in the OpenSSL operation.
std::optional<brillo::Blob> Aes256GcmEncrypt(const brillo::SecureBlob& key,
                                             const brillo::Blob& auth_data,
                                             const brillo::SecureBlob& input);

// Authenticated decryption of |input| using AES-GCM-256 with |key| and
// |auth_data|.
//
// Assumes the 12-byte IV used during encryption is appended to |input|.
//
// Returns std::nullopt if there's an error in the OpenSSL operation.
std::optional<brillo::SecureBlob> Aes256GcmDecrypt(
    const brillo::SecureBlob& key,
    const brillo::Blob& auth_data,
    const brillo::Blob& input);

}  // namespace context
}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONTEXT_OPENSSL_UTILS_H_
