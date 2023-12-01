// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_crypto.h"

#include <base/strings/string_number_conversions.h>
#include <chromeos/ec/ec_commands.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace biod {

bool BiodCrypto::ComputeValidationValue(const brillo::SecureVector& secret,
                                        const std::string& user_id,
                                        std::vector<uint8_t>* out) {
  std::vector<uint8_t> user_id_bytes;

  if (!base::HexStringToBytes(user_id, &user_id_bytes))
    return false;
  // Pad user_id so that we have exactly the same user_id as FPMCU has.
  // Otherwise the user_id length is different and validation value is wrong.
  user_id_bytes.resize(FP_CONTEXT_USERID_WORDS * sizeof(uint32_t));
  out->resize(SHA256_DIGEST_LENGTH);

  return HMAC(EVP_sha256(), secret.data(), secret.size(), user_id_bytes.data(),
              user_id_bytes.size(), out->data(), nullptr) != nullptr;
}

}  // namespace biod
