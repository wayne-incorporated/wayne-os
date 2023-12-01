// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <memory>
#include <vector>

#include <base/logging.h>
#include "shill/profile.h"

namespace shill {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

class ShillProfileFuzz {
 public:
  static void Run(const uint8_t* data, size_t size) {
    Profile::Identifier parsed;
    const std::string fuzzed_str(reinterpret_cast<const char*>(data), size);
    Profile::ParseIdentifier(fuzzed_str, &parsed);
    Profile::IsValidIdentifierToken(fuzzed_str);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  ShillProfileFuzz::Run(data, size);
  return 0;
}

}  // namespace shill
