// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <vector>

#include <base/check_op.h>
#include <base/containers/span.h>
#include <base/logging.h>

#include "common/still_capture_processor_impl.h"

namespace cros {

namespace {

struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOG_FATAL); }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  std::vector<uint8_t> data_copy(data, data + size);

  std::vector<uint8_t> buffer;
  std::map<uint16_t, base::span<uint8_t>> index;
  if (ParseAppSectionsForTesting(base::make_span(data_copy), &buffer, &index)) {
    // Validate the returned indices to point into the buffer.
    for (const auto& item : index) {
      CHECK_LE(buffer.data(), item.second.data());
      CHECK_LE(item.second.data() + item.second.size(),
               buffer.data() + buffer.size());
    }
  }

  return 0;
}

}  // namespace cros
