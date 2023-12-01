// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "typecd/daemon.h"

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader);

  LOG(INFO) << "Starting Type C daemon.\n";
  typecd::Daemon daemon;

  daemon.Run();
  return 0;
}
