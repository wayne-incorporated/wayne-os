// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "shill/network/dhcpv4_config.h"

namespace shill {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

class DHCPv4ConfigStaticRoutesFuzz {
 public:
  static void Run(const uint8_t* data, size_t size) {
    IPConfig::Properties properties;
    const std::string fuzzed_str(reinterpret_cast<const char*>(data), size);
    DHCPv4Config::ParseClasslessStaticRoutes(fuzzed_str, &properties);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  DHCPv4ConfigStaticRoutesFuzz::Run(data, size);
  return 0;
}

}  // namespace shill
