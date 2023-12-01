// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This tool provides a basic CLI to control battery saver mode (BSM)
// on ChromeOS.

#include "power_manager/tools/battery_saver/battery_saver.h"

#include <unistd.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <absl/strings/str_format.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/run_loop.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <dbus/bus.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>
#include <power_manager-client/power_manager/dbus-proxies.h>

#include "power_manager/tools/battery_saver/battery_saver_mode_watcher.h"
#include "power_manager/tools/battery_saver/proto_util.h"

namespace power_manager {
namespace {

using org::chromium::PowerManagerProxy;
using org::chromium::PowerManagerProxyInterface;

// CLI documentation.
constexpr base::StringPiece kUsage = R"(Usage: battery_saver <command>

A tool for inspecting and updating the state of ChromeOS Battery Saver
Mode (BSM).

Commands:
  enable            Enable battery saver mode.

  disable           Disable battery saver mode.

  status            Print the current status of BSM to stdout.
                    On success, writes the string "enabled" or "disabled".
)";

// Fetch the current state of BSM, and print either "enabled" or "disabled"
// to stdout.
absl::Status PrintBsmStatus(PowerManagerProxyInterface& proxy) {
  absl::StatusOr<BatterySaverModeState> result = GetBsmState(proxy);
  if (!result.ok()) {
    return result.status();
  }

  if (result->enabled()) {
    std::cout << "enabled\n";
  } else {
    std::cout << "disabled\n";
  }
  return absl::OkStatus();
}

absl::Status MonitorBsmStatus(PowerManagerProxyInterface& proxy) {
  std::cout << "Monitoring for battery saver mode changes.\n";

  // Watch D-Bus for BSM state updates.
  base::RunLoop loop;
  absl::Status result = absl::OkStatus();
  BatterySaverModeWatcher watcher(
      proxy, base::BindRepeating(
                 [](base::RunLoop* loop, absl::Status* result,
                    absl::StatusOr<BatterySaverModeState> new_state) {
                   // If an error was encountered, record it in `result` and
                   // abort the loop.
                   if (!new_state.ok()) {
                     *result = absl::InternalError(absl::StrCat(
                         "Monitoring failed: ", new_state.status().message()));
                     loop->Quit();
                     return;
                   }

                   // Otherwise, print the new status to stdout.
                   std::cout << BatterySaverModeStateToString(*new_state)
                             << "\n";
                 },
                 base::Unretained(&loop), base::Unretained(&result)));

  // Monitor until the user aborts with Ctrl+C or an error is received.
  loop.Run();

  return result;
}

absl::Status RunCommand(BsmCommand command) {
  // Connect to D-Bus.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  auto bus = base::MakeRefCounted<dbus::Bus>(options);
  if (!bus->Connect()) {
    return absl::UnknownError("Failed to connect to system D-Bus.");
  }
  PowerManagerProxy proxy(bus);

  // Run the command.
  switch (command) {
    case BsmCommand::kEnable:
      return SetBsmEnabled(proxy, true);
    case BsmCommand::kDisable:
      return SetBsmEnabled(proxy, false);
    case BsmCommand::kStatus:
      return PrintBsmStatus(proxy);
    case BsmCommand::kMonitor:
      return MonitorBsmStatus(proxy);
  }
}

}  // namespace

// Convert a BatterySaverModeState proto into a string suitable for logging.
std::string BatterySaverModeStateToString(const BatterySaverModeState& state) {
  // The proto generates the MessageLite API, so the standard DebugString()
  // methods are not available. Instead, we manually render a string.
  return absl::StrFormat("{ enabled: %s; cause: %s }",
                         state.enabled() ? "true" : "false",
                         BatterySaverModeState::Cause_Name(state.cause()));
}

absl::StatusOr<BatterySaverModeState> GetBsmState(
    PowerManagerProxyInterface& proxy) {
  // Send the request to powerd.
  std::vector<uint8_t> proto_bytes;
  brillo::ErrorPtr error;
  proxy.GetBatterySaverModeState(&proto_bytes, &error);
  if (error) {
    return absl::UnknownError(base::StringPrintf(
        "Failed to fetch current battery saver mode state: %s",
        error->GetFirstError()->GetMessage().c_str()));
  }

  // Deserialize the state bytes.
  std::optional<BatterySaverModeState> result =
      DeserializeProto<BatterySaverModeState>(proto_bytes);
  if (!result.has_value()) {
    return absl::UnknownError("Failed to deserialize server's response.");
  }

  return result.value();
}

// Set Battery Saver Mode to the given state.
absl::Status SetBsmEnabled(PowerManagerProxyInterface& proxy, bool enable) {
  // Enable power saver mode.
  power_manager::SetBatterySaverModeStateRequest request;
  request.set_enabled(enable);
  brillo::ErrorPtr error;
  proxy.SetBatterySaverModeState(SerializeProto(request), &error);
  if (error) {
    return absl::UnknownError(
        base::StringPrintf("Failed to update battery saver mode state: %s",
                           error->GetFirstError()->GetMessage().c_str()));
  }

  return absl::OkStatus();
}

absl::StatusOr<BsmCommand> ParseCommandLine(int argc, const char* const* argv) {
  // Parse the command line.
  if (!brillo::FlagHelper::Init(argc, argv, std::string(kUsage),
                                brillo::FlagHelper::InitFuncType::kReturn)) {
    return absl::InvalidArgumentError("Invalid option specified.");
  }

  // Parse the command name.
  std::vector<std::string> commands =
      base::CommandLine::ForCurrentProcess()->GetArgs();
  if (commands.size() != 1) {
    return absl::InvalidArgumentError("Expected exactly one command.");
  }
  if (commands[0] == "enable") {
    return BsmCommand::kEnable;
  }
  if (commands[0] == "disable") {
    return BsmCommand::kDisable;
  }
  if (commands[0] == "status") {
    return BsmCommand::kStatus;
  }
  if (commands[0] == "monitor") {
    return BsmCommand::kMonitor;
  }
  return absl::InvalidArgumentError(
      base::StringPrintf("Unknown command '%s'.", commands[0].c_str()));
}

int BatterySaverCli(int argc, const char* const argv[]) {
  base::SingleThreadTaskExecutor executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher file_descriptor_watcher(executor.task_runner());

  // Parse arguments.
  absl::StatusOr<BsmCommand> command = ParseCommandLine(argc, argv);
  if (!command.ok()) {
    std::cerr << "Invalid command line arguments: "
              << command.status().message() << "\n\n"
              << "Run with `--help` for help.\n";
    return 1;
  }

  // Run the given command.
  if (absl::Status status = RunCommand(command.value()); !status.ok()) {
    std::cerr << "Error: " << status.message() << "\n";
    return 1;
  }

  return 0;
}

}  // namespace power_manager
