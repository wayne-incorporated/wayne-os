// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/xml/android_xml_util.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "base/logging.h"

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  std::string out_fingerprint;
  std::string out_sdk_version;

  while (data_provider.remaining_bytes()) {
    // Cannot use |ConsumeRandomLengthString| in a loop because it can enter
    // infinite loop by always returning empty string.
    size_t cur_line_size = data_provider.ConsumeIntegralInRange<size_t>(
        0, data_provider.remaining_bytes());
    std::string cur_line = data_provider.ConsumeBytesAsString(cur_line_size);

    if (arc::FindFingerprintAndSdkVersion(&out_fingerprint, &out_sdk_version,
                                          cur_line)) {
      return 0;
    }
  }

  return 0;
}
