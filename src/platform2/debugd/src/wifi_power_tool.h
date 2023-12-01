// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_WIFI_POWER_TOOL_H_
#define DEBUGD_SRC_WIFI_POWER_TOOL_H_

#include <string>

namespace debugd {

// Gets and sets WiFi power save mode.
class WifiPowerTool {
 public:
  WifiPowerTool() = default;
  WifiPowerTool(const WifiPowerTool&) = delete;
  WifiPowerTool& operator=(const WifiPowerTool&) = delete;

  ~WifiPowerTool() = default;

  // Sets the power save mode and returns the new mode, or an error.
  std::string SetWifiPowerSave(bool enable) const;

  // Returns the current power save mode.
  std::string GetWifiPowerSave() const;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_WIFI_POWER_TOOL_H_
