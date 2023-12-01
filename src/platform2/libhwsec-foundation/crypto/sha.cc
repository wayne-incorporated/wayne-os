// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/sha.h"

#include <openssl/sha.h>

namespace hwsec_foundation {

namespace {

template <class T, class U>
T Sha1Helper(const U& data) {
  SHA_CTX sha_context;
  unsigned char md_value[SHA_DIGEST_LENGTH];
  T hash;

  SHA1_Init(&sha_context);
  SHA1_Update(&sha_context, data.data(), data.size());
  SHA1_Final(md_value, &sha_context);
  hash.resize(sizeof(md_value));
  memcpy(hash.data(), md_value, sizeof(md_value));
  // Zero the stack to match expectations set by SecureBlob.
  brillo::SecureClearContainer(md_value);
  return hash;
}

template <class T, class U>
T Sha256Helper(const U& data) {
  SHA256_CTX sha_context;
  unsigned char md_value[SHA256_DIGEST_LENGTH];
  T hash;

  SHA256_Init(&sha_context);
  SHA256_Update(&sha_context, data.data(), data.size());
  SHA256_Final(md_value, &sha_context);
  hash.resize(sizeof(md_value));
  memcpy(hash.data(), md_value, sizeof(md_value));
  // Zero the stack to match expectations set by SecureBlob.
  brillo::SecureClearContainer(md_value);
  return hash;
}

}  // namespace

brillo::Blob Sha1(const brillo::Blob& data) {
  return Sha1Helper<brillo::Blob, brillo::Blob>(data);
}

brillo::SecureBlob Sha1ToSecureBlob(const brillo::Blob& data) {
  return Sha1Helper<brillo::SecureBlob, brillo::Blob>(data);
}

brillo::SecureBlob Sha1(const brillo::SecureBlob& data) {
  return Sha1Helper<brillo::SecureBlob, brillo::SecureBlob>(data);
}

brillo::Blob Sha256(const brillo::Blob& data) {
  return Sha256Helper<brillo::Blob, brillo::Blob>(data);
}

brillo::SecureBlob Sha256ToSecureBlob(const brillo::Blob& data) {
  return Sha256Helper<brillo::SecureBlob, brillo::Blob>(data);
}

brillo::SecureBlob Sha256(const brillo::SecureBlob& data) {
  return Sha256Helper<brillo::SecureBlob, brillo::SecureBlob>(data);
}

}  // namespace hwsec_foundation
