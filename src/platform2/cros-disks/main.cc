// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "cros-disks/daemon.h"
#include "cros-disks/process.h"

int main(int argc, char** argv) {
  DEFINE_bool(foreground, false, "Run in foreground");
  DEFINE_bool(no_session_manager, false,
              "Run without the expectation of a session manager");
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");
  brillo::FlagHelper::Init(argc, argv, "Chromium OS Disk Daemon");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetMinLogLevel(FLAGS_log_level);

  if (!FLAGS_foreground)
    PCHECK(daemon(0, 0) == 0);

  LOG(INFO) << "Service started";
  const int ret = cros_disks::Daemon(!FLAGS_no_session_manager).Run();
  LOG(INFO) << "Service stopped with " << cros_disks::Process::ExitCode(ret);

  return ret;
}
