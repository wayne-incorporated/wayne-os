// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_oci/run_oci_utils.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace run_oci {
namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  auto data_provider{FuzzedDataProvider(data, size)};
  std::vector<std::string> options;
  for (size_t i{0}; i < data_provider.ConsumeIntegralInRange(0, 255); ++i) {
    options.emplace_back(data_provider.ConsumeRandomLengthString(1024));
  }

  // While these are all out-params, there's no harm in making sure
  // there are no failures _if_ they are read by ParseMountOptions.
  int mount_flags_out{data_provider.ConsumeIntegral<int>()};
  int negated_mount_flags_out{data_provider.ConsumeIntegral<int>()};
  int bind_mount_flags_out{data_provider.ConsumeIntegral<int>()};
  int mount_propagation_flags_out{data_provider.ConsumeIntegral<int>()};
  bool loopback_out{data_provider.ConsumeBool()};
  std::string verity_options{data_provider.ConsumeRandomLengthString(255)};

  ParseMountOptions(options, &mount_flags_out, &negated_mount_flags_out,
                    &bind_mount_flags_out, &mount_propagation_flags_out,
                    &loopback_out, &verity_options);
  return 0;
}

}  // namespace
}  // namespace run_oci
