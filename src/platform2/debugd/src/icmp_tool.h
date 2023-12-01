// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_ICMP_TOOL_H_
#define DEBUGD_SRC_ICMP_TOOL_H_

#include <map>
#include <string>

namespace debugd {

class ICMPTool {
 public:
  ICMPTool() = default;
  ICMPTool(const ICMPTool&) = delete;
  ICMPTool& operator=(const ICMPTool&) = delete;

  ~ICMPTool() = default;

  std::string TestICMP(const std::string& host);
  std::string TestICMPWithOptions(
      const std::string& host,
      const std::map<std::string, std::string>& options);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_ICMP_TOOL_H_
