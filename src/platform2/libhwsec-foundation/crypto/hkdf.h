// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_HKDF_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_HKDF_H_

#include <brillo/secure_blob.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// The list of possible hashes for HKDF operations. For now we only need
// SHA-256, but the list can be easily extended if required.
enum class HkdfHash { kSha256 };

// Derives HKDF from `key`, `info` and `salt` and stores as
// `result` of a desired `result_len`. If `result_len` is zero, the resulting
// key length will be equal to hash size. This is equivalent to calling
// HkdfExtract and HkdfExpand, where the result of HkdfExtract is passed to
// HkdfExpand. Returns false if operation failed.
bool HWSEC_FOUNDATION_EXPORT Hkdf(HkdfHash hash,
                                  const brillo::SecureBlob& key,
                                  const brillo::SecureBlob& info,
                                  const brillo::SecureBlob& salt,
                                  size_t result_len,
                                  brillo::SecureBlob* result);

// Performs HKDF expand operation from `key` and `info` and stores
// as `result` of a desired `result_len`. If `result_len` is zero, the resulting
// key length will be equal to hash size. See RFC 5869 for detailed description.
// Returns false if operation failed.
bool HWSEC_FOUNDATION_EXPORT HkdfExpand(HkdfHash hash,
                                        const brillo::SecureBlob& key,
                                        const brillo::SecureBlob& info,
                                        size_t result_len,
                                        brillo::SecureBlob* result);

// Performs HKDF extract operation from `key` and `salt` and stores
// `result`. The length of the result is determined by `hash` function used,
// e.g. for SHA-256 the length is equal to SHA256_DIGEST_LENGTH. See RFC 5869
// for detailed description. Returns false if operation failed.
bool HWSEC_FOUNDATION_EXPORT HkdfExtract(HkdfHash hash,
                                         const brillo::SecureBlob& key,
                                         const brillo::SecureBlob& salt,
                                         brillo::SecureBlob* result);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_HKDF_H_
