// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/minijail/minijail.h>
#include <brillo/syslog_logging.h>
#include <mojo/core/embedder/embedder.h>

#include "shill/daemon_task.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/shill_config.h"
#include "shill/shill_daemon.h"
#include "shill/technology.h"

namespace {

namespace switches {

// Don't daemon()ize; run in foreground.
const char kForeground[] = "foreground";
// Don't attempt to manage these devices.
const char kDevicesBlocked[] = "devices-blocked";
// Manage only these devices.
const char kDevicesAllowed[] = "devices-allowed";
// Ignore Ethernet-like devices that don't have any driver information.
const char kIgnoreUnknownEthernet[] = "ignore-unknown-ethernet";
// Flag that causes shill to show the help message and exit.
const char kHelp[] = "help";

// The help message shown if help flag is passed to the program.
const char kHelpMessage[] =
    "\n"
    "Available Switches: \n"
    "  --foreground\n"
    "    Don\'t daemon()ize; run in foreground.\n"
    "  --devices-blocked=device1,device2\n"
    "    Do not manage devices named device1 or device2\n"
    "  --devices-allowed=device1,device2\n"
    "    Manage only devices named device1 and device2\n"
    "  --ignore-unknown-ethernet\n"
    "    Ignore Ethernet-like devices that do not report a driver\n"
    "  --log-level=N\n"
    "    Logging level:\n"
    "      0 = LOG(INFO), 1 = LOG(WARNING), 2 = LOG(ERROR),\n"
    "      -1 = SLOG(..., 1), -2 = SLOG(..., 2), etc.\n"
    "  --log-scopes=\"*scope1+scope2\".\n"
    "    Scopes to enable for SLOG()-based logging.\n"
    "  --passive-mode\n"
    "    Do not manage any devices by default\n"
    "  --default-technology-order=technology1,technology2\n"
    "    Specify the default priority order of the technologies.\n";
}  // namespace switches

const char kLoggerCommand[] = "/usr/bin/logger";
const char kLoggerUser[] = "syslog";

// Always logs to the syslog and logs to stderr if
// we are running in the foreground.
void SetupLogging(bool foreground, const char* daemon_name) {
  int log_flags = 0;
  log_flags |= brillo::kLogToSyslog;
  log_flags |= brillo::kLogHeader;
  if (foreground) {
    log_flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(log_flags);

  if (!foreground) {
    std::vector<char*> logger_command_line;
    int logger_stdin_fd;
    logger_command_line.push_back(const_cast<char*>(kLoggerCommand));
    logger_command_line.push_back(const_cast<char*>("--priority"));
    logger_command_line.push_back(const_cast<char*>("daemon.err"));
    logger_command_line.push_back(const_cast<char*>("--tag"));
    logger_command_line.push_back(const_cast<char*>(daemon_name));
    logger_command_line.push_back(nullptr);

    brillo::Minijail* minijail = brillo::Minijail::GetInstance();
    struct minijail* jail = minijail->New();
    minijail->DropRoot(jail, kLoggerUser, kLoggerUser);

    if (!minijail->RunPipeAndDestroy(jail, logger_command_line, nullptr,
                                     &logger_stdin_fd)) {
      LOG(ERROR) << "Unable to spawn logger. "
                 << "Writes to stderr will be discarded.";
      return;
    }

    // Note that we don't set O_CLOEXEC here. This means that stderr
    // from any child processes will, by default, be logged to syslog.
    if (dup2(logger_stdin_fd, fileno(stderr)) != fileno(stderr)) {
      PLOG(ERROR) << "Failed to redirect stderr to syslog";
    }
    close(logger_stdin_fd);
  }
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  if (cl->HasSwitch(switches::kHelp)) {
    LOG(INFO) << switches::kHelpMessage;
    return 0;
  }

  shill::DaemonTask::Settings settings;

  if (cl->HasSwitch(switches::kDevicesBlocked)) {
    settings.devices_blocked =
        base::SplitString(cl->GetSwitchValueASCII(switches::kDevicesBlocked),
                          ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  }

  if (cl->HasSwitch(switches::kDevicesAllowed)) {
    settings.devices_allowed =
        base::SplitString(cl->GetSwitchValueASCII(switches::kDevicesAllowed),
                          ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  }

  settings.ignore_unknown_ethernet =
      cl->HasSwitch(switches::kIgnoreUnknownEthernet);

  // Initialize Mojo for the whole process.
  mojo::core::Init();

  shill::Config config;
  // Construct the daemon first, so we get our AtExitManager.
  shill::ShillDaemon daemon(settings, &config);

  // Configure logging before we start anything else, so early log messages go
  // to a consistent place.
  SetupLogging(cl->HasSwitch(switches::kForeground), argv[0]);
  shill::SetLogLevelFromCommandLine(cl);

  // Go for it!
  daemon.Run();

  LOG(INFO) << "Process exiting.";

  return 0;
}
