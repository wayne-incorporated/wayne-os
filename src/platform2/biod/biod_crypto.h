// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_CRYPTO_H_
#define BIOD_BIOD_CRYPTO_H_

#include <string>
#include <vector>

#include <brillo/secure_blob.h>

namespace biod {

class BiodCrypto {
 public:
  static bool ComputeValidationValue(const brillo::SecureVector& secret,
                                     const std::string& user_id,
                                     std::vector<uint8_t>* out);
};

}  // namespace biod

#endif  // BIOD_BIOD_CRYPTO_H_
