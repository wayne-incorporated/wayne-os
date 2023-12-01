// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "chaps/chaps_utility.h"

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  size_t input_size = sizeof(CK_RSA_PKCS_PSS_PARAMS);
  // Have a small chance of providing a string with an invalid size.
  if (data_provider.ConsumeIntegral<uint8_t>() == 1) {
    auto invalid_input_size = data_provider.ConsumeIntegral<uint8_t>();
    static_assert(
        std::numeric_limits<decltype(invalid_input_size)>::max() >
            sizeof(CK_RSA_PKCS_PSS_PARAMS),
        "Input type should be able to represent sizes too small or too large.");
    input_size = invalid_input_size;
  }

  if (data_provider.remaining_bytes() < input_size)
    return 0;

  const CK_RSA_PKCS_PSS_PARAMS* params_out;
  const EVP_MD* hash_out;
  chaps::DigestAlgorithm signing_algorithm =
      chaps::DigestAlgorithm(data_provider.ConsumeIntegral<int>());
  chaps::DigestAlgorithm digest_algorithm_out;
  const std::string inputs = data_provider.ConsumeBytesAsString(input_size);
  chaps::ParseRSAPSSParams(inputs, signing_algorithm, &params_out, &hash_out,
                           &digest_algorithm_out);
  return 0;
}
