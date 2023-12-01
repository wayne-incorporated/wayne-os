// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/arc_property_util.h"

#include <stddef.h>
#include <stdint.h>

#include <fuzzer/FuzzedDataProvider.h>

#include <map>
#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>

namespace {
constexpr size_t kMaxInputSize = 64 * 1024;
}

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Limit the input size to avoid timing out on ClusterFuzz.
  if (size > kMaxInputSize)
    return 0;

  FuzzedDataProvider data_provider(data, size);

  std::string content = data_provider.ConsumeRandomLengthString(size);

  brillo::FakeCrosConfig config;
  while (data_provider.remaining_bytes()) {
    // Cannot use |ConsumeRandomLengthString| in a loop because it can enter an
    // infinite loop by always returning an empty string.

    size_t path_size = data_provider.ConsumeIntegralInRange<size_t>(
        0, data_provider.remaining_bytes());
    std::string path =
        std::string("/") + data_provider.ConsumeBytesAsString(path_size);

    if (data_provider.remaining_bytes() == 0)
      break;

    size_t property_size = data_provider.ConsumeIntegralInRange<size_t>(
        1, data_provider.remaining_bytes());
    std::string property = data_provider.ConsumeBytesAsString(property_size);

    if (data_provider.remaining_bytes() == 0)
      break;

    size_t val_size = data_provider.ConsumeIntegralInRange<size_t>(
        1, data_provider.remaining_bytes());
    std::string val = data_provider.ConsumeBytesAsString(val_size);

    config.SetString(path, property, val);
  }

  std::string expanded_content;
  arc::ExpandPropertyContentsForTesting(content, &config, false,
                                        &expanded_content);

  return 0;
}
