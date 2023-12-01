// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "crosdns/crosdns_daemon.h"

int main(int argc, char* argv[]) {
  int log_flags = brillo::kLogToSyslog | brillo::kLogToStderrIfTty;
  brillo::InitLog(log_flags);

  LOG(INFO) << "Starting CrOS DNS daemon";

  crosdns::CrosDnsDaemon daemon;
  return daemon.Run();
}
