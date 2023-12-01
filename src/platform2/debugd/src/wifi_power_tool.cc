// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/wifi_power_tool.h"

#include <linux/capability.h>
#include <net/if.h>

#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

const char kIwPath[] = "/usr/sbin/iw";
const uint64_t kIwCapabilities = CAP_TO_MASK(CAP_NET_ADMIN);

bool RunIwCommand(bool set, bool enable, std::string* output) {
  bool success = false;
  ProcessWithOutput p;
  p.SetCapabilities(kIwCapabilities);
  if (!p.Init()) {
    *output = "<process init failed>";
    return false;
  }
  p.AddArg(kIwPath);
  p.AddArg("dev");
  // Chrome OS WiFi device is either mlan0 or wlan0.
  if (if_nametoindex("mlan0")) {
    p.AddArg("mlan0");
  } else if (if_nametoindex("wlan0")) {
    p.AddArg("wlan0");
  } else {
    *output = "<no wifi device found>";
    return false;
  }
  if (set) {
    p.AddArg("set");
  } else {
    p.AddArg("get");
  }
  p.AddArg("power_save");
  if (set) {
    p.AddArg(enable ? "on" : "off");
  }
  if (p.Run() == 0) {
    success = true;
  }
  p.GetOutput(output);
  return success;
}

}  // namespace

std::string WifiPowerTool::SetWifiPowerSave(bool enable) const {
  std::string result;
  if (!RunIwCommand(true, enable, &result)) {
    return result;
  }
  // Return the new state (successful set has no output)
  return GetWifiPowerSave();
}

std::string WifiPowerTool::GetWifiPowerSave() const {
  std::string result;
  RunIwCommand(false, false, &result);
  return result;
}

}  // namespace debugd
