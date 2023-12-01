// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/common/attestation_crypto.h"

#include <optional>
#include <string>

#include <base/logging.h>
#include <crypto/sha2.h>

#include "hwsec-test-utils/common/openssl_utility.h"

namespace hwsec_test_utils {
namespace attestation_crypto {

namespace {

// Servers prepend these 2 headers to the same seed to calculate AES key and
// HMAC key respectively.
constexpr char kHashHeaderForEncrypt[] = "ENCRYPT";
constexpr char kHashHeaderForMac[] = "MAC";

}  // namespace

std::string KeyDeriverDirect::ToAesKey(const std::string& seed) const {
  return seed;
}

std::string KeyDeriverDirect::ToHmacKey(const std::string& seed) const {
  return seed;
}

std::string KeyDeriverSha256WithHeader::ToAesKey(
    const std::string& seed) const {
  return crypto::SHA256HashString(kHashHeaderForEncrypt + seed);
}

std::string KeyDeriverSha256WithHeader::ToHmacKey(
    const std::string& seed) const {
  return crypto::SHA256HashString(kHashHeaderForMac + seed);
}

ReturnStatus Decrypt(const attestation::EncryptedData& encrypted_data_proto,
                     const crypto::ScopedEVP_PKEY& key,
                     const KeyDeriverBase& key_deriver,
                     std::string* decrypted) {
  // Decrypt.
  std::optional<std::string> seed = EVPRsaDecrypt(
      key, encrypted_data_proto.wrapped_key(), RSA_PKCS1_OAEP_PADDING);
  if (!seed) {
    return ReturnStatus::kUnwrapKey;
  }
  const std::string aes_key = key_deriver.ToAesKey(*seed);
  std::optional<std::string> decrypted_data =
      EVPAesDecrypt(encrypted_data_proto.encrypted_data(), EVP_aes_256_cbc(),
                    aes_key, encrypted_data_proto.iv());
  if (!decrypted_data) {
    LOG(ERROR) << __func__ << ": Failed to decrypt data.";
    return ReturnStatus::kDecrypt;
  }

  // Verify HMAC.
  const std::string hmac_key_str = key_deriver.ToHmacKey(*seed);
  crypto::ScopedEVP_PKEY hmac_key(EVP_PKEY_new_mac_key(
      EVP_PKEY_HMAC, nullptr,
      reinterpret_cast<const unsigned char*>(hmac_key_str.data()),
      hmac_key_str.length()));
  if (!hmac_key) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_new_mac_key: "
               << GetOpenSSLError();
    return ReturnStatus::kFailure;
  }
  std::optional<std::string> hmac = EVPDigestSign(
      hmac_key, EVP_sha512(),
      encrypted_data_proto.iv() + encrypted_data_proto.encrypted_data());
  if (!hmac) {
    LOG(ERROR) << __func__ << ": Failed to calculate HMAC.";
    return ReturnStatus::kFailure;
  }
  if (*hmac != encrypted_data_proto.mac()) {
    LOG(ERROR) << __func__ << ": HMAC mismatch.";
    return ReturnStatus::kHmac;
  }
  *decrypted = *decrypted_data;
  return ReturnStatus::kSuccess;
}

}  // namespace attestation_crypto

}  // namespace hwsec_test_utils
