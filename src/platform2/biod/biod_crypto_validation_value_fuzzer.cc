// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/sha.h>

#include "biod/biod_crypto.h"

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  std::vector<uint8_t> result;
  FuzzedDataProvider data_provider(data, size);

  std::string user_id = data_provider.ConsumeRandomLengthString(size);
  std::vector<uint8_t> remaining_bytes =
      data_provider.ConsumeRemainingBytes<uint8_t>();
  brillo::SecureVector secret(remaining_bytes.cbegin(), remaining_bytes.cend());

  biod::BiodCrypto::ComputeValidationValue(secret, user_id, &result);

  return 0;
}
