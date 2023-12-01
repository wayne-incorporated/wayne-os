// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "system-proxy/system_proxy_daemon.h"

int main(int /* argc */, char* /* argv */[]) {
  brillo::OpenLog("system_proxy", true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Run daemon.
  LOG(INFO) << "system_proxy starting";
  system_proxy::SystemProxyDaemon daemon;
  int result = daemon.Run();
  LOG(INFO) << "system_proxy stopping with exit code " << result;

  return result;
}
