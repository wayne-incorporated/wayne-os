// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_SHA_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_SHA_H_

#include <brillo/secure_blob.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// TODO(jorgelo,crbug.com/728047): Review current usage of these functions and
// consider making the functions that take a plain Blob also return a plain
// Blob.
brillo::Blob HWSEC_FOUNDATION_EXPORT Sha1(const brillo::Blob& data);
brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
Sha1ToSecureBlob(const brillo::Blob& data);
brillo::SecureBlob HWSEC_FOUNDATION_EXPORT Sha1(const brillo::SecureBlob& data);

brillo::Blob HWSEC_FOUNDATION_EXPORT Sha256(const brillo::Blob& data);
brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
Sha256ToSecureBlob(const brillo::Blob& data);
brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
Sha256(const brillo::SecureBlob& data);
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_SHA_H_
