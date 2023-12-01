// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "pciguard/daemon.h"
#include "pciguard/sysfs_utils.h"

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  pciguard::SysfsUtils utils;
  // Check if this invocation is for a one time job instead of a daemon.
  if (cl->HasSwitch("deauthorize-all-devs")) {
    LOG(INFO) << " called with --deauthorize-all-devs";
    return utils.DeauthorizeAllDevices();
  } else if (cl->HasSwitch("authorize-all-devs")) {
    LOG(INFO) << " called with --authorize-all-devs";
    return utils.AuthorizeAllDevices();
  }

  LOG(INFO) << "Starting pciguard daemon.\n";
  pciguard::Daemon daemon;

  daemon.Run();
  return 0;
}
