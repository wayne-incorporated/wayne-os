// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/syslog_logging.h>

#include "arc/setup/arc_setup.h"

int main(int argc, char** argv) {
  base::ElapsedTimer timer;

  brillo::OpenLog("arc-remove-stale-data", true /*log_pid*/);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  LOG(INFO) << "Starting arc-remove-stale-data";

  arc::ArcSetup(arc::Mode::REMOVE_STALE_DATA, base::FilePath()).Run();

  LOG(INFO) << "arc-remove-stale-data took "
            << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
  return 0;
}
