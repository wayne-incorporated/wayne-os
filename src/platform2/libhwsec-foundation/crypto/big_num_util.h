// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_BIG_NUM_UTIL_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_BIG_NUM_UTIL_H_

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bn.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// TODO(b:182154354): Move to Chrome crypto library.
using ScopedBN_CTX = crypto::ScopedOpenSSL<BN_CTX, BN_CTX_free>;

// Creates context for big number operations. Returns nullptr if error occurred.
ScopedBN_CTX HWSEC_FOUNDATION_EXPORT CreateBigNumContext();

// Creates big number with undefined value. Returns nullptr if error occurred.
crypto::ScopedBIGNUM HWSEC_FOUNDATION_EXPORT CreateBigNum();

// Creates BIGNUM and set it to a given value. Returns nullptr if error
// occurred. This is useful for testing, otherwise shouldn't be used.
crypto::ScopedBIGNUM HWSEC_FOUNDATION_EXPORT BigNumFromValue(BN_ULONG value);

// Converts SecureBlob to BIGNUM. Returns nullptr if error occurred.
// Empty SecureBlob is interpreted as zero.
// The input SecureBlob is expected to be in big-endian encoding.
crypto::ScopedBIGNUM HWSEC_FOUNDATION_EXPORT
SecureBlobToBigNum(const brillo::SecureBlob& blob);

// Converts BIGNUM to SecureBlob padded to a given `result_len`. Returns false
// if error occurred, otherwise stores resulting blob in `result`. The resulting
// SecureBlob is encoded in big-endian form.
// This is the only method that should be used for converting BIGNUMs to
// SecureBlobs, as it is not advised to create variable length SecureBlobs for
// security reasons.
bool HWSEC_FOUNDATION_EXPORT BigNumToSecureBlob(const BIGNUM& bn,
                                                int result_len,
                                                brillo::SecureBlob* result);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_BIG_NUM_UTIL_H_
