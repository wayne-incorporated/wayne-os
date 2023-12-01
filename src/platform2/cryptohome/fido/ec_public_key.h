// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FIDO_EC_PUBLIC_KEY_H_
#define CRYPTOHOME_FIDO_EC_PUBLIC_KEY_H_

#include "cryptohome/fido/public_key.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <crypto/scoped_openssl_types.h>
#include <brillo/secure_blob.h>

#include <base/containers/span.h>

namespace cryptohome {
namespace fido_device {

// See https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data for
// COSE (CBOR Object Signing and Encryption) algorithm name standard.
constexpr char kEccAlgName[] = "ES256";

using BinaryValue = std::vector<uint8_t>;

// This class holds a COSE-encoded ECC public key and provides utility functions
// to convert COSE key to OpenSSL DER key.
class ECPublicKey : public PublicKey {
 public:
  static std::unique_ptr<ECPublicKey> ParseECPublicKey(
      base::span<const uint8_t> cose_encoded_public_key);

  ~ECPublicKey() = default;

  std::vector<uint8_t> EncodeAsCOSEKey() const override;
  void SetCOSEKey(std::vector<uint8_t> cose_key);

  // Convert the current public key to OpenSSL EC_KEY*.
  crypto::ScopedEC_KEY GetEC_KEY() const;

  // Dump the current key to DER format.
  bool DumpToDer(brillo::SecureBlob* der) override;

  // Get OpenSSL algorithm numeric identifier (NID). If the algorithm is not
  // supported, return -1.
  std::optional<int> GetAlgorithmNid() const;

  // Print the public key to string format.
  std::string ToString() override;

  // Return the x value of the public key point
  BinaryValue GetX() const;

  // Return the y value of the public key point
  BinaryValue GetY() const;

 private:
  ECPublicKey();
  // Parse EC key from COSE-encoded public key.
  bool ParseCOSE(base::span<const uint8_t> bytes);

  std::vector<uint8_t> cose_encoding_;
  BinaryValue x_;
  BinaryValue y_;
};

}  // namespace fido_device
}  // namespace cryptohome

#endif  // CRYPTOHOME_FIDO_EC_PUBLIC_KEY_H_
