// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include "kerberos/kerberos_daemon.h"

int main(int /* argc */, char* /* argv */[]) {
  brillo::OpenLog("kerberosd", true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Run daemon.
  LOG(INFO) << "kerberosd starting";
  kerberos::KerberosDaemon daemon;
  int result = daemon.Run();
  LOG(INFO) << "kerberosd stopping with exit code " << result;

  return result;
}
