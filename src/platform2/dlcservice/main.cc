// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/syslog_logging.h>

#include "dlcservice/daemon.h"

int main(int argc, char** argv) {
  brillo::OpenLog("dlcservice", true);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader);

  return dlcservice::Daemon().Run();
}
