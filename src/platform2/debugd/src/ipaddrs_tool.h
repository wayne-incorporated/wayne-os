// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_IPADDRS_TOOL_H_
#define DEBUGD_SRC_IPADDRS_TOOL_H_

#include <string>
#include <vector>

#include <brillo/variant_dictionary.h>

namespace debugd {

class IpAddrsTool {
 public:
  IpAddrsTool() = default;
  IpAddrsTool(const IpAddrsTool&) = delete;
  IpAddrsTool& operator=(const IpAddrsTool&) = delete;

  ~IpAddrsTool() = default;

  std::vector<std::string> GetIpAddresses(
      const brillo::VariantDictionary& options);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_IPADDRS_TOOL_H_
