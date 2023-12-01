// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_SECURE_BLOB_UTIL_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_SECURE_BLOB_UTIL_H_

#include <string>

#include <brillo/secure_blob.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

HWSEC_FOUNDATION_EXPORT void GetSecureRandom(unsigned char* bytes, size_t len);
HWSEC_FOUNDATION_EXPORT brillo::SecureBlob CreateSecureRandomBlob(
    size_t length);

// Encodes a binary blob to hex-ascii. Similar to base::HexEncode but
// produces lowercase letters for hex digits.
//
// Parameters
//   blob - The binary blob to convert
HWSEC_FOUNDATION_EXPORT std::string BlobToHex(const brillo::Blob& blob);
HWSEC_FOUNDATION_EXPORT std::string SecureBlobToHex(
    const brillo::SecureBlob& blob);

// Parameters
//   blob - The binary blob to convert
//   buffer (IN/OUT) - Where to store the converted blob
//   buffer_length - The size of the buffer
HWSEC_FOUNDATION_EXPORT void BlobToHexToBuffer(const brillo::Blob& blob,
                                               void* buffer,
                                               size_t buffer_length);
HWSEC_FOUNDATION_EXPORT void SecureBlobToHexToBuffer(
    const brillo::SecureBlob& blob, void* buffer, size_t buffer_length);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_SECURE_BLOB_UTIL_H_
