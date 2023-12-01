// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <base/at_exit.h>
#pragma GCC diagnostic pop
#include <base/logging.h>

#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
  base::AtExitManager at_exit;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // NetChecksum
  NetChecksum(data, size);

  // Ipv4Checksum
  iphdr ip;
  memcpy(&ip, data, std::min(size, sizeof(iphdr)));
  Ipv4Checksum(&ip);

  // Udpv4Checksum
  Udpv4Checksum(data, size);

  // Icmpv6Checksum
  Icmpv6Checksum(data, size);

  // GetIpFamily
  std::string ip_address(reinterpret_cast<const char*>(data), size);
  GetIpFamily(ip_address);

  return 0;
}

}  // namespace
}  // namespace patchpanel
