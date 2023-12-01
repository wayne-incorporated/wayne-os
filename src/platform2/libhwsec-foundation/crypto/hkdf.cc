// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/hkdf.h"

#include <base/logging.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#include "libhwsec-foundation/crypto/error_util.h"

namespace hwsec_foundation {

namespace {

// Derives HKDF from `key`. The parameters `info` and `salt` are optional
// depending on the mode. For EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND both `info`
// and `salt` must be provided, otherwise for EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY
// only `salt` and for EVP_PKEY_HKDEF_MODE_EXPAND_ONLY only `info`. If
// `result_len` is zero, the resulting key length will be equal to hash size.
// Returns false if error occurred.
bool HkdfInternal(HkdfHash hash,
                  const brillo::SecureBlob& key,
                  const brillo::SecureBlob* info,
                  const brillo::SecureBlob* salt,
                  int mode,
                  size_t result_len,
                  brillo::SecureBlob* result) {
  crypto::ScopedEVP_PKEY_CTX context(
      EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
  if (!context) {
    LOG(ERROR) << "Failed to initialize EVP_PKEY_CTX: " << GetOpenSSLErrors();
    return false;
  }
  if (EVP_PKEY_derive_init(context.get()) <= 0) {
    LOG(ERROR) << "Failed to initialize HKDF: " << GetOpenSSLErrors();
    return false;
  }
  if (EVP_PKEY_CTX_hkdf_mode(context.get(), mode) <= 0) {
    LOG(ERROR) << "Failed to set HKDF mode: " << GetOpenSSLErrors();
    return false;
  }
  const EVP_MD* md = nullptr;
  switch (hash) {
    case HkdfHash::kSha256:
      md = EVP_sha256();
      break;
  }
  if (!md) {
    LOG(ERROR) << "Invalid HKDF hash type: " << static_cast<int>(hash);
    return false;
  }
  if (result_len == 0) {
    // Assign resulting key length to hash size.
    result_len = EVP_MD_size(md);
  }
  if (EVP_PKEY_CTX_set_hkdf_md(context.get(), md) <= 0) {
    LOG(ERROR) << "Failed to set HKDF message digest: " << GetOpenSSLErrors();
    return false;
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(context.get(), key.data(), key.size()) <= 0) {
    LOG(ERROR) << "Failed to set HKDF key: " << GetOpenSSLErrors();
    return false;
  }
  if (salt && EVP_PKEY_CTX_set1_hkdf_salt(context.get(), salt->data(),
                                          salt->size()) <= 0) {
    LOG(ERROR) << "Failed to set HKDF salt: " << GetOpenSSLErrors();
    return false;
  }
  if (info && EVP_PKEY_CTX_add1_hkdf_info(context.get(), info->data(),
                                          info->size()) <= 0) {
    LOG(ERROR) << "Failed to set HKDF info: " << GetOpenSSLErrors();
    return false;
  }
  // Derive HKDF.
  result->resize(result_len);
  if (EVP_PKEY_derive(context.get(), result->data(), &result_len) <= 0) {
    LOG(ERROR) << "Failed to derive HKDF: " << GetOpenSSLErrors();
    return false;
  }
  if (result_len != result->size()) {
    LOG(ERROR) << "Failed to derive HKDF of length " << result->size()
               << ", the resulting length " << result_len;
    return false;
  }
  return true;
}

}  // namespace

bool Hkdf(HkdfHash hash,
          const brillo::SecureBlob& key,
          const brillo::SecureBlob& info,
          const brillo::SecureBlob& salt,
          size_t result_len,
          brillo::SecureBlob* result) {
  return HkdfInternal(hash, key, &info, &salt,
                      EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND, result_len,
                      result);
}

bool HkdfExpand(HkdfHash hash,
                const brillo::SecureBlob& key,
                const brillo::SecureBlob& info,
                size_t result_len,
                brillo::SecureBlob* result) {
  return HkdfInternal(hash, key, &info, /*salt=*/nullptr,
                      EVP_PKEY_HKDEF_MODE_EXPAND_ONLY, result_len, result);
}

bool HkdfExtract(HkdfHash hash,
                 const brillo::SecureBlob& key,
                 const brillo::SecureBlob& salt,
                 brillo::SecureBlob* result) {
  return HkdfInternal(hash, key, /*info=*/nullptr, &salt,
                      EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY, /*result_len=*/0,
                      result);
}

}  // namespace hwsec_foundation
