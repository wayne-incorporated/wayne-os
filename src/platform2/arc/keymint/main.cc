// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <brillo/syslog_logging.h>

#include "arc/keymint/daemon.h"
#include "arc/keymint/keymint_logger.h"

int main(int argc, char** argv) {
  // arc-keymintd takes no command line arguments.
  base::CommandLine::Init(argc, argv);
  // Logging to system logs in /var/log/arc.log.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  // Setup keymint logger.
  arc::keymint::KeyMintLogger();

  LOG(INFO) << "Running Daemon";
  arc::keymint::Daemon daemon;
  return daemon.Run();
}
