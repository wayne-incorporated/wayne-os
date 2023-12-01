// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_CRYPTO_H_
#define SHILL_STORE_CRYPTO_H_

#include <optional>
#include <string>

namespace shill {

// Used to migrate Profile storage from the old ROT47 format to plaintext.
// TODO(crbug.com/1084279) Remove this and friends after migration to plaintext
// is complete.
namespace Crypto {

// Returns |plaintext| encrypted by the highest priority available crypto
// module capable of performing the operation.
std::string Encrypt(const std::string& plaintext);

// Returns |ciphertext| decrypted by the highest priority available crypto
// module capable of performing the operation. If no module succeeds, returns
// std::nullopt.
std::optional<std::string> Decrypt(const std::string& ciphertext);

}  // namespace Crypto

}  // namespace shill

#endif  // SHILL_STORE_CRYPTO_H_
