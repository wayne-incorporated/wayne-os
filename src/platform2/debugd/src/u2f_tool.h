// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_U2F_TOOL_H_
#define DEBUGD_SRC_U2F_TOOL_H_

#include <string>

namespace debugd {

// Tool to tweak u2fd daemon.
class U2fTool {
 public:
  U2fTool() = default;
  U2fTool(const U2fTool&) = delete;
  U2fTool& operator=(const U2fTool&) = delete;

  ~U2fTool() = default;

  // Set override/debugging flags for u2fd.
  std::string SetFlags(const std::string& flags);

  // Get current flags.
  std::string GetFlags() const;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_U2F_TOOL_H_
