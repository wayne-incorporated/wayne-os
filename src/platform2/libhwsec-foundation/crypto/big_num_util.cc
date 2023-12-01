// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/big_num_util.h"

#include <base/logging.h>

#include "libhwsec-foundation/crypto/error_util.h"

namespace hwsec_foundation {

ScopedBN_CTX CreateBigNumContext() {
  ScopedBN_CTX bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure: " << GetOpenSSLErrors();
    return nullptr;
  }
  return bn_ctx;
}

crypto::ScopedBIGNUM CreateBigNum() {
  crypto::ScopedBIGNUM result(BN_secure_new());
  if (!result) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure: " << GetOpenSSLErrors();
    return nullptr;
  }
  return result;
}

crypto::ScopedBIGNUM BigNumFromValue(BN_ULONG value) {
  crypto::ScopedBIGNUM result(BN_secure_new());
  if (!result) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure: " << GetOpenSSLErrors();
    return nullptr;
  }
  if (BN_set_word(result.get(), value) != 1) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure: " << GetOpenSSLErrors();
    return nullptr;
  }
  return result;
}

crypto::ScopedBIGNUM SecureBlobToBigNum(const brillo::SecureBlob& blob) {
  crypto::ScopedBIGNUM result(BN_secure_new());
  if (!result) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure: " << GetOpenSSLErrors();
    return nullptr;
  }
  if (!BN_bin2bn(blob.data(), blob.size(), result.get())) {
    LOG(ERROR) << "Failed to convert SecureBlob to BIGNUM: "
               << GetOpenSSLErrors();
    return nullptr;
  }
  return result;
}

bool BigNumToSecureBlob(const BIGNUM& bn,
                        int result_len,
                        brillo::SecureBlob* result) {
  result->resize(result_len);
  if (BN_bn2binpad(&bn, result->data(), result_len) < 0) {
    LOG(ERROR) << "Failed to convert BIGNUM to SecureBlob: "
               << GetOpenSSLErrors();
    return false;
  }
  return true;
}

}  // namespace hwsec_foundation
