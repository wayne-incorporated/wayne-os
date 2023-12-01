// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/secure_string.h"

#include <openssl/crypto.h>

namespace brillo {

BRILLO_DISABLE_ASAN void SecureClearBytes(void* v, size_t n) {
  OPENSSL_cleanse(v, n);
}

int SecureMemcmp(const void* s1, const void* s2, size_t n) {
  return CRYPTO_memcmp(s1, s2, n);
}

}  // namespace brillo
