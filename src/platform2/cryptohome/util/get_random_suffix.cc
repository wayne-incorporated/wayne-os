// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/util/get_random_suffix.h"

#include <string>

#include <openssl/rand.h>

namespace cryptohome {

std::string GetRandomSuffix() {
  const int kBufferSize = 6;
  unsigned char buffer[kBufferSize];
  if (RAND_bytes(buffer, kBufferSize) < 0) {
    return "";
  }
  std::string suffix;
  for (int i = 0; i < kBufferSize; ++i) {
    int random_value = buffer[i] % (2 * 26 + 10);
    if (random_value < 26) {
      suffix.push_back('a' + random_value);
    } else if (random_value < 2 * 26) {
      suffix.push_back('A' + random_value - 26);
    } else {
      suffix.push_back('0' + random_value - 2 * 26);
    }
  }
  return suffix;
}

}  // namespace cryptohome
