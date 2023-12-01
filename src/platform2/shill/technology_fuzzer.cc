// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <base/logging.h>

#include "shill/error.h"
#include "shill/technology.h"

namespace shill {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

class ShillTechnologyFuzz {
 public:
  static void Run(const uint8_t* data, size_t size) {
    const std::string fuzzed_str(reinterpret_cast<const char*>(data), size);
    std::vector<shill::Technology> technologies;
    shill::Error error;
    shill::GetTechnologyVectorFromString(fuzzed_str, &technologies, &error);
    TechnologyFromName(fuzzed_str);
    TechnologyFromStorageGroup(fuzzed_str);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  ShillTechnologyFuzz::Run(data, size);
  return 0;
}

}  // namespace shill
