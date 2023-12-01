// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>

#include <array>
#include <string>

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <vboot/crossystem.h>

#include "debugd/src/process_with_output.h"

namespace {

const char kUsageMessage[] =
    "\n"
    "Enables booting from USB or queries whether USB booting is enabled.\n"
    "\n";

// Checks if |full_string| starts with |prefix|.
bool StartsWith(const std::string& full_string, const std::string& prefix) {
  return !full_string.compare(0, prefix.length(), prefix);
}

// Checks if USB boot is already enabled. This is indicated differently on
// some boards:
//   Mario: Cannot boot from USB.
//   Alex and ZGB: USB boot is enabled if crossystem mainfw_type is "developer".
//   Other: USB boot is enabled if crossystem dev_boot_usb is 1.
bool IsUsbBootEnabled() {
  std::array<char, VB_MAX_STRING_PROPERTY> crossystem_buffer;
  if (VbGetSystemPropertyString("fwid", crossystem_buffer.data(),
                                crossystem_buffer.size()) == 0) {
    std::string fwid(crossystem_buffer.data());
    // Older fwid strings (including Mario/Alex/ZGB) are <platform>.<version>.
    if (StartsWith(fwid, "Mario.")) {
      return false;
    } else if (StartsWith(fwid, "Alex.") || StartsWith(fwid, "ZGB.")) {
      if (VbGetSystemPropertyString("mainfw_type", crossystem_buffer.data(),
                                    crossystem_buffer.size()) == 0) {
        return !strcmp(crossystem_buffer.data(), "developer");
      }
      return false;
    } else {
      return VbGetSystemPropertyInt("dev_boot_usb") == 1;
    }
  }
  return false;
}

// Enables USB boot.
bool EnableUsbBoot() {
  std::string error;
  int result = debugd::ProcessWithOutput::RunProcessFromHelper(
      "enable_dev_usb_boot", debugd::ProcessWithOutput::ArgList{},
      nullptr,  // stdin.
      nullptr,  // stdout.
      &error);  // stderr.
  if (result != EXIT_SUCCESS) {
    LOG(WARNING) << "\"enable_dev_usb_boot\" failed with exit code " << result
                 << ": " << error;
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(q, false, "Query whether USB booting is enabled");
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  if (FLAGS_q) {
    return IsUsbBootEnabled() ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  return EnableUsbBoot() ? EXIT_SUCCESS : EXIT_FAILURE;
}
