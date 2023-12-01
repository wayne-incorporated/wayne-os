// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_HMAC_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_HMAC_H_

#include <string>

#include <brillo/secure_blob.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
HmacSha512(const brillo::SecureBlob& key, const brillo::Blob& data);
brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
HmacSha512(const brillo::SecureBlob& key, const brillo::SecureBlob& data);

brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
HmacSha256(const brillo::SecureBlob& key, const brillo::Blob& data);
brillo::SecureBlob HWSEC_FOUNDATION_EXPORT
HmacSha256(const brillo::SecureBlob& key, const brillo::SecureBlob& data);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_HMAC_H_
