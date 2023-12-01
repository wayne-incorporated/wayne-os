// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_TOOLS_BATTERY_SAVER_BATTERY_SAVER_H_
#define POWER_MANAGER_TOOLS_BATTERY_SAVER_BATTERY_SAVER_H_

#include <string>

#include <absl/status/statusor.h>
#include <base/memory/scoped_refptr.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>
#include <power_manager-client/power_manager/dbus-proxies.h>

namespace power_manager {

// Main entry point to the CLI tool, called by main().
//
// Separated from main() to allow unit tests (which require their own `main`
// implementation) to call into it.
int BatterySaverCli(int argc, const char* const argv[]);

//
// Functions and types below exposed for testing.
//

// Top-level command for the tool to run.
enum class BsmCommand {
  kEnable,   // "enable"
  kDisable,  // "disable"
  kStatus,   // "status"
  kMonitor,  // "monitor"
};

// Parse the given command line, producing a `BsmCommand` on success.
absl::StatusOr<BsmCommand> ParseCommandLine(int argc, const char* const* argv);

// Set Battery Saver Mode to the given state.
absl::Status SetBsmEnabled(org::chromium::PowerManagerProxyInterface& proxy,
                           bool enable);

// Get the current state of BSM.
absl::StatusOr<BatterySaverModeState> GetBsmState(
    org::chromium::PowerManagerProxyInterface& proxy);

// Convert a BatterySaverModeState proto into a string suitable for logging.
std::string BatterySaverModeStateToString(const BatterySaverModeState& state);

}  // namespace power_manager

#endif  // POWER_MANAGER_TOOLS_BATTERY_SAVER_BATTERY_SAVER_H_
