// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_UTILITY_CRYPTO_H_
#define LIBHWSEC_FOUNDATION_UTILITY_CRYPTO_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bn.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {
namespace utility {

// RAII version of OpenSSL BN_CTX, with auto-initialization on instantiation and
// auto-cleanup on leaving scope.
class HWSEC_FOUNDATION_EXPORT ScopedBN_CTX {
 public:
  ScopedBN_CTX() : ctx_(BN_CTX_new()) { BN_CTX_start(ctx_); }

  ~ScopedBN_CTX() {
    BN_CTX_end(ctx_);
    BN_CTX_free(ctx_);
  }

  BN_CTX* get() { return ctx_; }

 private:
  BN_CTX* ctx_;
};

// Creates and returns a secure random blob with the given |length|. In case of
// an error, returns an empty blob.
HWSEC_FOUNDATION_EXPORT brillo::SecureBlob CreateSecureRandomBlob(
    size_t length);

// Gets the latest OpenSSL error in the following format:
//   error:[error code]:[library name]:[function name]:[reason string]
HWSEC_FOUNDATION_EXPORT std::string GetOpensslError();

// Convert RSA key (with public and/or private key set) key to the binary DER
// encoded SubjectPublicKeyInfo format.
//
// Return nullopt if key is null, or OpenSSL returned error.
HWSEC_FOUNDATION_EXPORT std::optional<std::vector<uint8_t>>
RsaKeyToSubjectPublicKeyInfoBytes(const crypto::ScopedRSA& key);

// Convert ECC key (with public and/or private key set) key to the binary DER
// encoded SubjectPublicKeyInfo format.
//
// Return nullopt if key is null, or OpenSSL returned error.
HWSEC_FOUNDATION_EXPORT std::optional<std::vector<uint8_t>>
EccKeyToSubjectPublicKeyInfoBytes(const crypto::ScopedEC_KEY& key);

}  // namespace utility
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_UTILITY_CRYPTO_H_
