// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/kdf.h"

#include <crypto/scoped_openssl_types.h>
#include <crypto/sha2.h>

#include <optional>

#include "hwsec-test-utils/common/openssl_utility.h"

#include <base/check.h>
#include <base/logging.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

std::string KDFe(const std::string& z,
                 const std::string& use,
                 const std::string& party_u_info,
                 const std::string& party_v_info) {
  const std::string counter{'\x00', '\x00', '\x00', '\x01'};
  const std::string null_terminated{'\x00'};
  CHECK(null_terminated.size() == 1 && !null_terminated[0]);
  const std::string other_info =
      use + null_terminated + party_u_info + party_v_info;
  return crypto::SHA256HashString(counter + z + other_info);
}

std::optional<std::string> KDFa(const std::string& key,
                                const std::string& label,
                                const std::string& context_u,
                                const std::string& context_v,
                                int bits) {
  CHECK(bits == 128 || bits == 256);
  const std::string counter{'\x00', '\x00', '\x00', '\x01'};
  const std::string null_terminated{'\x00'};
  CHECK(null_terminated.size() == 1 && !null_terminated[0]);
  const std::string context = context_u + context_v;
  const std::string length(
      bits == 128 ? "\x00\x00\x00\x80" /* 128 */ : "\x00\x00\x01\x00" /* 256 */,
      4);

  // Create HMAC key.
  crypto::ScopedEVP_PKEY hmac_key(EVP_PKEY_new_mac_key(
      EVP_PKEY_HMAC, nullptr,
      reinterpret_cast<const unsigned char*>(key.data()), key.length()));
  if (!hmac_key) {
    LOG(ERROR) << __func__ << ": Failed to call EVP_PKEY_new_mac_key: "
               << GetOpenSSLError();
    return {};
  }
  std::optional<std::string> hmac =
      EVPDigestSign(hmac_key, EVP_sha256(),
                    counter + label + null_terminated + context + length);
  if (!hmac) {
    LOG(ERROR) << __func__ << ": Failed to calculate HMAC.";
    return {};
  }
  return hmac->substr(0, bits / 8);
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils
