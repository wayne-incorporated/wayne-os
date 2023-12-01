// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/syslog_logging.h>

#include "minios/daemon.h"

int main() {
  brillo::OpenLog("minios", /*log_pid=*/true);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader);
  return minios::Daemon().Run();
}
