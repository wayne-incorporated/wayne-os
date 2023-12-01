// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "arc/keymaster/daemon.h"
#include "arc/keymaster/keymaster_logger.h"

int main(int argc, char** argv) {
  // Keymasterd takes no command line arguments.
  base::CommandLine::Init(argc, argv);
  // Logging to system logs in /var/log/arc.log.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  // Setup keymaster logger.
  arc::keymaster::KeymasterLogger();

  LOG(INFO) << "Running Daemon";
  arc::keymaster::Daemon daemon;
  return daemon.Run();
}
