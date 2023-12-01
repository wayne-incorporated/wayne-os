// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "cros-camera/common.h"
#include "diagnostics/camera_diagnostics.h"

static void SetLogItems() {
  constexpr bool kOptionPID = true;
  constexpr bool kOptionTID = true;
  constexpr bool kOptionTimestamp = true;
  constexpr bool kOptionTickcount = true;
  logging::SetLogItems(kOptionPID, kOptionTID, kOptionTimestamp,
                       kOptionTickcount);
}

int main(int argc, char* argv[]) {
  // Init CommandLine for InitLogging.
  base::CommandLine::Init(argc, argv);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  // Override the log items set by brillo::InitLog.
  SetLogItems();
  brillo::FlagHelper::Init(argc, argv, "Camera diagnostics service");

  // Create the daemon instance first to properly set up MessageLoop and
  // AtExitManager.
  brillo::Daemon daemon;

  cros::CameraDiagnostics camera_diagnostics;
  // Setup camera diagnostics mojo IPC.
  camera_diagnostics.Start();

  LOGF(INFO) << "Starting DAEMON cros-camera-diagnostics service";
  daemon.Run();
  LOGF(INFO) << "End DAEMON cros-camera-diagnostics service";

  return 0;
}
