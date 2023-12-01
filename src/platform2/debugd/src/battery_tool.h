// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_BATTERY_TOOL_H_
#define DEBUGD_SRC_BATTERY_TOOL_H_

#include <string>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class BatteryTool : public SubprocessTool {
 public:
  BatteryTool() = default;
  BatteryTool(const BatteryTool&) = delete;
  BatteryTool& operator=(const BatteryTool&) = delete;

  ~BatteryTool() override = default;

  std::string BatteryFirmware(const std::string& option);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_BATTERY_TOOL_H_
