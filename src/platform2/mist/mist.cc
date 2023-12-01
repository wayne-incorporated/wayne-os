// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/mist.h"

#include <stdlib.h>

#include <iostream>  // NOLINT(readability/streams)
#include <memory>
#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/syslog_logging.h>

#include "mist/context.h"
#include "mist/event_dispatcher.h"
#include "mist/usb_modem_one_shot_switcher.h"
#include "mist/usb_modem_switch_context.h"
#include "mist/usb_modem_switcher.h"

namespace mist {

namespace {

const int kDefaultLogLevel = 0;  // LOG(INFO)

const char kCommandIsSupported[] = "is-supported";
const char kCommandMonitor[] = "monitor";
const char kCommandSwitch[] = "switch";

const char kSwitchDaemon[] = "daemon";
const char kSwitchLogLevel[] = "log-level";
const char kSwitchHelp[] = "help";

const char kUsageMessage[] =
    "Usage: mist [--help] [--log-level=<level>] <command> [<arguments>]\n"
    "\n"
    "mist is a utility for switching 3G/4G USB dongles into the modem mode.\n"
    "\n"
    "Available commands:\n"
    "  is-supported <sys-path>  Query if device on <sys-path> is supported.\n"
    "  monitor                  Monitor and switch new devices to modem mode.\n"
    "  switch <sys-path>        Switch device on <sys-path> to modem mode.\n"
    "\n"
    "Available switches:\n"
    "  --daemon                 Run in daemon mode.\n"
    "  --log-level=<level>      Set the logging level. Levels are:\n"
    "                              2: LOG(ERROR)\n"
    "                              1: LOG(WARNING)\n"
    "                              0: LOG(INFO) - default\n"
    "                             -1: VLOG(1)\n"
    "                             -2: VLOG(2), etc\n"
    "  --help                   Show this help.\n"
    "\n";

}  // namespace

int Mist::Run(base::CommandLine* command_line) {
  // Switch: --help
  if (command_line->HasSwitch(kSwitchHelp)) {
    std::cout << kUsageMessage;
    return EXIT_SUCCESS;
  }

  // Switch: --log-level <level>
  int log_level = kDefaultLogLevel;
  if (command_line->HasSwitch(kSwitchLogLevel)) {
    std::string log_level_str =
        command_line->GetSwitchValueASCII(kSwitchLogLevel);
    if (!base::StringToInt(log_level_str, &log_level)) {
      std::cerr << "WARNING: Invalid log level '" << log_level_str << "'.\n";
    }
  }

  // <command> [<arguments>]
  base::CommandLine::StringVector arguments = command_line->GetArgs();
  if (arguments.empty()) {
    std::cout << kUsageMessage;
    return EXIT_SUCCESS;
  }

  const std::string& command = arguments[0];

  int log_flags = brillo::kLogToSyslog;
  if (command_line->HasSwitch(kSwitchDaemon)) {
    PLOG_IF(FATAL, ::daemon(0, 0) == 1) << "Could not create a daemon.";
  } else {
    log_flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(log_flags);
  logging::SetMinLogLevel(log_level);

  Context context;
  if (!context.Initialize())
    return EXIT_FAILURE;

  // Command: monitor
  if (command == kCommandMonitor) {
    // TODO(benchan): Handle SIGINT and SIGTERM.
    UsbModemSwitcher switcher(&context);
    switcher.Start();
    context.event_dispatcher()->DispatchForever();
    return EXIT_SUCCESS;
  }

  // Command: is-supported <sys-path>
  // Command: switch <sys-path>
  if (command == kCommandIsSupported || command == kCommandSwitch) {
    if (arguments.size() < 2) {
      std::cerr << "ERROR: No device sysfs path is specified.\n";
      return EXIT_FAILURE;
    }

    auto switch_context = std::make_unique<UsbModemSwitchContext>();

    const std::string& sys_path = arguments[1];
    // Following the POSIX convention, return EXIT_SUCCESS if the device is
    // supported or EXIT_FAILURE otherwise.
    bool supported = switch_context->InitializeFromSysPath(&context, sys_path);
    if (!supported) {
      std::cerr << "ERROR: Device '" << sys_path
                << "' is not supported by mist.\n";
      return EXIT_FAILURE;
    }

    if (command == kCommandSwitch) {
      UsbModemOneShotSwitcher switcher(&context);
      switcher.Start(switch_context.release());
      context.event_dispatcher()->DispatchForever();
      if (!switcher.is_success()) {
        std::cerr << "ERROR: Could not switch device '" << sys_path
                  << "' to the modem mode.\n";
        return EXIT_FAILURE;
      }
    }

    return EXIT_SUCCESS;
  }

  // Unknown command
  std::cerr << "ERROR: Unknown command '" << command << "'.";
  return EXIT_FAILURE;
}

}  // namespace mist
