// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_CLIENT_UTIL_H_
#define U2FD_CLIENT_UTIL_H_

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/sha.h>

#include "u2fd/client/u2f_client_export.h"

namespace u2f {

namespace util {

//
// Utility functions for copying data to/from vector<uint8_t>.
//
//////////////////////////////////////////////////////////////////////

// Utility function to copy an object, as raw bytes, to a vector.
template <typename FromType>
void U2F_CLIENT_EXPORT AppendToVector(const FromType& from,
                                      std::vector<uint8_t>* to) {
  const uint8_t* from_bytes = reinterpret_cast<const uint8_t*>(&from);
  std::copy(from_bytes, from_bytes + sizeof(from), std::back_inserter(*to));
}

// Specializations of above function for copying from vector and string.
template <>
void U2F_CLIENT_EXPORT AppendToVector(const std::vector<uint8_t>& from,
                                      std::vector<uint8_t>* to);
template <>
void U2F_CLIENT_EXPORT AppendToVector(const std::string& from,
                                      std::vector<uint8_t>* to);

// Utility function to transform a string to a vector.
std::vector<uint8_t> U2F_CLIENT_EXPORT ToVector(const std::string& str);

// Utility function to copy bytes from a vector to an object. This is the
// inverse of AppendToVector.
template <typename VectorAllocator, typename ToType>
bool U2F_CLIENT_EXPORT
VectorToObject(const std::vector<uint8_t, VectorAllocator>& from,
               ToType* to,
               const size_t size) {
  if (size < from.size()) {
    return false;
  }
  memcpy(to, &from.front(), from.size());
  return true;
}

// Utility function to copy part of a string to a vector.
void U2F_CLIENT_EXPORT AppendSubstringToVector(const std::string& from,
                                               int start,
                                               int length,
                                               std::vector<uint8_t>* to);

//
// Crypto utilities.
//
//////////////////////////////////////////////////////////////////////

// Attempts to convert the specified ECDSA signature (specified as r and s
// values) to DER encoding; returns std::nullopt on error.
std::optional<std::vector<uint8_t>> U2F_CLIENT_EXPORT SignatureToDerBytes(
    const std::vector<uint8_t>& r, const std::vector<uint8_t>& s);

// Returns the SHA-256 of the specified data.
template <typename Blob>
std::vector<uint8_t> U2F_CLIENT_EXPORT Sha256(const Blob& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256_CTX sha_context;

  SHA256_Init(&sha_context);
  SHA256_Update(&sha_context, &data.front(), data.size());
  SHA256_Final(&hash.front(), &sha_context);

  return hash;
}

// Returns the HMAC_SHA-256 of the specified data.
std::vector<uint8_t> U2F_CLIENT_EXPORT
HmacSha256(const brillo::SecureBlob& key, const std::vector<uint8_t>& data);

// Attest to |data_to_sign| using software attestation.
bool U2F_CLIENT_EXPORT
DoSoftwareAttest(const std::vector<uint8_t>& data_to_sign,
                 std::vector<uint8_t>* attestation_cert,
                 std::vector<uint8_t>* signature);

// Creates a new EC key to use for U2F attestation.
crypto::ScopedEC_KEY U2F_CLIENT_EXPORT CreateAttestationKey();

// Signs data using attestion_key, and returns the DER-encoded signature,
// or std::nullopt on error.
std::optional<std::vector<uint8_t>> U2F_CLIENT_EXPORT
AttestToData(const std::vector<uint8_t>& data, EC_KEY* attestation_key);

// Returns an X509 certificate for the specified attestation_key, to be included
// in a U2F register response, or std::nullopt on error.
std::optional<std::vector<uint8_t>> U2F_CLIENT_EXPORT
CreateAttestationCertificate(EC_KEY* attestation_key);

// Parses the specified certificate and re-serializes it to the same vector,
// removing any padding that was present.
bool U2F_CLIENT_EXPORT RemoveCertificatePadding(std::vector<uint8_t>* cert);

// Builds data to be signed as part of a U2F_REGISTER response, as defined
// by the "U2F Raw Message Formats" specification.
std::vector<uint8_t> U2F_CLIENT_EXPORT
BuildU2fRegisterResponseSignedData(const std::vector<uint8_t>& app_id,
                                   const std::vector<uint8_t>& challenge,
                                   const std::vector<uint8_t>& pub_key,
                                   const std::vector<uint8_t>& key_handle);

std::optional<brillo::Blob> U2F_CLIENT_EXPORT
ParseSerialNumberFromCert(const brillo::Blob& cert_template);

}  // namespace util
}  // namespace u2f

#endif  // U2FD_CLIENT_UTIL_H_
