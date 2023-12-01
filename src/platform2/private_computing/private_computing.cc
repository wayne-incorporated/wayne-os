// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/syslog_logging.h>

#include "private_computing/private_computing_daemon.h"

int main(int /* argc */, char* /* argv */[]) {
  brillo::OpenLog("psm_device_active", true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Run Private Computing daemon.
  LOG(INFO) << "Private Computing daemon is starting.";
  private_computing::PrivateComputingDaemon daemon;
  int result = daemon.Run();
  LOG(INFO) << "Private Computing daemon is stopping with exit code " << result;

  return 0;
}
