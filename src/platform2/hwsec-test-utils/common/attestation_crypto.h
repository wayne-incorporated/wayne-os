// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_COMMON_ATTESTATION_CRYPTO_H_
#define HWSEC_TEST_UTILS_COMMON_ATTESTATION_CRYPTO_H_

#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <crypto/scoped_openssl_types.h>

namespace hwsec_test_utils {
namespace attestation_crypto {

// A functional interface that derives a input seed to the pair of AES and HMAC
// key.
class KeyDeriverBase {
 public:
  KeyDeriverBase() = default;
  ~KeyDeriverBase() = default;

  // Not copyable or movable.
  KeyDeriverBase(const KeyDeriverBase&) = delete;
  KeyDeriverBase(KeyDeriverBase&&) = delete;
  KeyDeriverBase& operator=(const KeyDeriverBase&) = delete;
  KeyDeriverBase& operator=(KeyDeriverBase&&) = delete;

  virtual std::string ToAesKey(const std::string& seed) const = 0;
  virtual std::string ToHmacKey(const std::string& seed) const = 0;
};

// |KeyDeriverDirect| returns the input |seed| as the AES key and HMAC key
// directly.
class KeyDeriverDirect : public KeyDeriverBase {
 public:
  KeyDeriverDirect() = default;
  ~KeyDeriverDirect() = default;

  // Not copyable or movable.
  KeyDeriverDirect(const KeyDeriverDirect&) = delete;
  KeyDeriverDirect(KeyDeriverDirect&&) = delete;
  KeyDeriverDirect& operator=(const KeyDeriverDirect&) = delete;
  KeyDeriverDirect& operator=(KeyDeriverDirect&&) = delete;

  // Overrides.
  std::string ToAesKey(const std::string& seed) const override;
  std::string ToHmacKey(const std::string& seed) const override;
};

// Derives a seed to AES and HMAC key with Sha256(HEADER||seed), where the
// HEADER is "ENCRYPT"/"HMAC", respectively.
class KeyDeriverSha256WithHeader : public KeyDeriverBase {
 public:
  KeyDeriverSha256WithHeader() = default;
  ~KeyDeriverSha256WithHeader() = default;

  // Not copyable or movable.
  KeyDeriverSha256WithHeader(const KeyDeriverSha256WithHeader&) = delete;
  KeyDeriverSha256WithHeader(KeyDeriverSha256WithHeader&&) = delete;
  KeyDeriverSha256WithHeader& operator=(const KeyDeriverSha256WithHeader&) =
      delete;
  KeyDeriverSha256WithHeader& operator=(KeyDeriverSha256WithHeader&&) = delete;

  // Overrides.
  std::string ToAesKey(const std::string& seed) const override;
  std::string ToHmacKey(const std::string& seed) const override;
};

// Indicates the success of an operation or the failure case of an operation.
enum class ReturnStatus {
  kSuccess,
  kUnwrapKey,
  kDecrypt,
  kHmac,
  kFailure,
};

// Decrypts the seed from |encrypted_data_proto| and derive it to the AES and
// the HMAC key. Then, decrypts the data in |encrypted_data_proto| and set the
// decrypted result to |decrypted|. In case of any error, returns the
// corresponding |ReturnStatus|. Otherwise, returns |kSuccess|. The
// implementation hardcodes the encryption algorithm to AES-256 with CBC cipher
// mode and the digest algorithm for HMAC to sha512, for that is the only case
// used in attestation.
ReturnStatus Decrypt(const attestation::EncryptedData& encrypted_data_proto,
                     const crypto::ScopedEVP_PKEY& key,
                     const KeyDeriverBase& key_derivation,
                     std::string* decrypted);

}  // namespace attestation_crypto

}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_COMMON_ATTESTATION_CRYPTO_H_
