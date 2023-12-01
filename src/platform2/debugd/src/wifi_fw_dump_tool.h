// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_WIFI_FW_DUMP_TOOL_H_
#define DEBUGD_SRC_WIFI_FW_DUMP_TOOL_H_

#include <string>

namespace debugd {

class WifiFWDumpTool {
 public:
  WifiFWDumpTool() = default;
  WifiFWDumpTool(const WifiFWDumpTool&) = delete;
  WifiFWDumpTool& operator=(const WifiFWDumpTool&) = delete;

  ~WifiFWDumpTool() = default;
  // Trigger WiFi firmware dumper.
  std::string WifiFWDump();
};

}  // namespace debugd

#endif  // DEBUGD_SRC_WIFI_FW_DUMP_TOOL_H_
