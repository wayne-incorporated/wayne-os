// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/utility/crypto.h"

#include <limits>
#include <optional>
#include <string>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

namespace {

// The wrapper of OpenSSL i2d series function. It takes a OpenSSL i2d function
// and apply to |object|.
//
// The wrapper will always accept the non-const pointer of the object since
// unique_ptr::get will only return the non-const version. It will break the
// type deduction of template.
template <typename OpenSSLType>
std::optional<std::vector<uint8_t>> OpenSSLObjectToBytes(
    int (*i2d_convert_function)(OpenSSLType*, unsigned char**),
    typename std::remove_const<OpenSSLType>::type* object) {
  if (object == nullptr) {
    return std::nullopt;
  }

  unsigned char* openssl_buffer = nullptr;

  int size = i2d_convert_function(object, &openssl_buffer);
  if (size < 0) {
    return std::nullopt;
  }

  crypto::ScopedOpenSSLBytes scoped_buffer(openssl_buffer);
  return std::vector<uint8_t>(openssl_buffer, openssl_buffer + size);
}

}  // namespace

namespace hwsec_foundation {
namespace utility {

brillo::SecureBlob CreateSecureRandomBlob(size_t length) {
  // OpenSSL takes a signed integer. Returns nullopt if the user requests
  // something too large.
  if (length > static_cast<size_t>(std::numeric_limits<int>::max())) {
    LOG(ERROR) << __func__ << ": length exceeds the limit of int.";
    return brillo::SecureBlob();
  }

  brillo::SecureBlob blob(length);
  if (!RAND_bytes(reinterpret_cast<unsigned char*>(blob.data()), length)) {
    LOG(ERROR) << __func__ << ": failed to generate " << length
               << " random bytes: " << GetOpensslError();
    return brillo::SecureBlob();
  }

  return blob;
}

std::string GetOpensslError() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* data = nullptr;
  int data_len = BIO_get_mem_data(bio, &data);
  std::string error_string(data, data_len);
  BIO_free(bio);
  return error_string;
}

std::optional<std::vector<uint8_t>> RsaKeyToSubjectPublicKeyInfoBytes(
    const crypto::ScopedRSA& key) {
  return OpenSSLObjectToBytes(i2d_RSA_PUBKEY, key.get());
}

std::optional<std::vector<uint8_t>> EccKeyToSubjectPublicKeyInfoBytes(
    const crypto::ScopedEC_KEY& key) {
  return OpenSSLObjectToBytes(i2d_EC_PUBKEY, key.get());
}

}  // namespace utility
}  // namespace hwsec_foundation
