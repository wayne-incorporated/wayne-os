// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "federated/daemon.h"

int main(int argc, char* argv[]) {
  brillo::FlagHelper::Init(argc, argv, argv[0]);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  if (!base::CommandLine::ForCurrentProcess()->GetArgs().empty()) {
    LOG(ERROR) << "Unexpected command line arguments";
    return 1;
  }

  federated::Daemon daemon;
  daemon.Run();
  return 0;
}
