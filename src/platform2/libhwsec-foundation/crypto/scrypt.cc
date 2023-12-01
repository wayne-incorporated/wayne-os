// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/scrypt.h"

#include <limits>
#include <utility>
#include <vector>

#include <malloc.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/numerics/safe_conversions.h>
#include <base/stl_util.h>
#include <brillo/secure_blob.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>

#include "libhwsec-foundation/crypto/aes.h"
#include "libhwsec-foundation/crypto/libscrypt_compat.h"
#include "libhwsec-foundation/crypto/secure_blob_util.h"

using brillo::SecureBlob;

namespace hwsec_foundation {

namespace {

class ConstBytePtr {
 public:
  explicit constexpr ConstBytePtr(const uint8_t* v) : value_(v) {}
  ConstBytePtr() = delete;

  // Allow implicit conversion to const unsigned char* and const char* and const
  // void*.
  constexpr operator const unsigned char*() const { return value_; }
  constexpr operator const char*() const {
    return static_cast<const char*>(static_cast<const void*>(value_));
  }
  constexpr operator void*() const {
    return const_cast<void*>(static_cast<const void*>(value_));
  }

 private:
  const uint8_t* value_;
};

// Global override-able for testing.
ScryptParameters gScryptParams = kDefaultScryptParams;

}  // namespace

bool DeriveSecretsScrypt(const brillo::SecureBlob& passkey,
                         const brillo::SecureBlob& salt,
                         std::vector<brillo::SecureBlob*> gen_secrets) {
  if (gen_secrets.empty()) {
    LOG(ERROR) << "No secrets requested from scrypt derivation.";
    return false;
  }
  size_t total_len = 0;
  for (auto& secret : gen_secrets) {
    if (secret->empty()) {
      LOG(ERROR) << "Empty secret requested from scrypt derivation.";
      return false;
    }
    total_len += secret->size();
  }

  SecureBlob generated(total_len);
  if (!Scrypt(passkey, salt, kDefaultScryptParams.n_factor,
              kDefaultScryptParams.r_factor, kDefaultScryptParams.p_factor,
              &generated)) {
    LOG(ERROR) << "Failed to derive scrypt keys from passkey.";
    return false;
  }

  uint8_t* data = generated.data();
  for (auto& value : gen_secrets) {
    value->assign(data, data + value->size());
    data += value->size();
  }

  return true;
}

bool Scrypt(const brillo::SecureBlob& input,
            const brillo::SecureBlob& salt,
            int work_factor,
            int block_size,
            int parallel_factor,
            brillo::SecureBlob* result) {
  crypto::ScopedEVP_PKEY_CTX pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL));
  if (EVP_PKEY_derive_init(pctx.get()) <= 0)
    return false;

  // OpenSSL 3.0 changed the input arg to const char*, other versions use const
  // unsigned char* or void*, so use ConstBytePtr to satisfy both.
  if (EVP_PKEY_CTX_set1_pbe_pass(pctx.get(), ConstBytePtr(input.data()),
                                 input.size()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set1_scrypt_salt(pctx.get(), salt.data(), salt.size()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_scrypt_N(pctx.get(), work_factor) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_scrypt_r(pctx.get(), block_size) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_scrypt_p(pctx.get(), parallel_factor) <= 0)
    return false;

  size_t outlen = result->size();
  int rc = EVP_PKEY_derive(pctx.get(), result->data(), &outlen);

  return rc > 0 && outlen == result->size();
}

bool DeprecatedEncryptScryptBlob(const brillo::SecureBlob& blob,
                                 const brillo::SecureBlob& key_source,
                                 brillo::SecureBlob* wrapped_blob) {
  wrapped_blob->resize(blob.size() + kScryptMetadataSize);

  brillo::SecureBlob salt = CreateSecureRandomBlob(kLibScryptSaltSize);
  brillo::SecureBlob derived_key(kLibScryptDerivedKeySize, '0');
  if (!Scrypt(key_source, salt, gScryptParams.n_factor, gScryptParams.r_factor,
              gScryptParams.p_factor, &derived_key) != 0) {
    LOG(ERROR) << "Failed to derive key with scrypt.";
    return false;
  }

  if (!LibScryptCompat::Encrypt(derived_key, salt, blob, gScryptParams,
                                wrapped_blob)) {
    LOG(ERROR) << "Failed to generate encrypted data.";
    return false;
  }

  return true;
}

void AssertProductionScryptParams() {
  // Always perform the check just in case.
  CHECK_EQ(kDefaultScryptParams.n_factor, gScryptParams.n_factor);
  CHECK_EQ(kDefaultScryptParams.r_factor, gScryptParams.r_factor);
  CHECK_EQ(kDefaultScryptParams.p_factor, gScryptParams.p_factor);
}

void SetScryptTestingParams() {
  gScryptParams = kTestScryptParams;
}

}  // namespace hwsec_foundation
