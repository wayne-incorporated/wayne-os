// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/timer/elapsed_timer.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "arc/setup/arc_setup.h"

int main(int argc, char** argv) {
  DEFINE_string(log_tag, "", "Tag to be used in syslog");

  base::ElapsedTimer timer;
  base::AtExitManager at_exit;

  brillo::FlagHelper::Init(argc, argv, "ARC prepare host_generated dir");

  CHECK(!FLAGS_log_tag.empty()) << "Must specify --log_tag";
  brillo::OpenLog(FLAGS_log_tag.c_str(), true /*log_pid*/);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  const std::string command_line =
      base::CommandLine::ForCurrentProcess()->GetCommandLineString();
  LOG(INFO) << "Starting " << command_line;
  arc::ArcSetup(arc::Mode::PREPARE_HOST_GENERATED_DIR,
                base::FilePath(USE_ARCVM ? arc::kVmConfigJson
                                         : arc::kContainerConfigJson))
      .Run();
  LOG(INFO) << command_line << " took "
            << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
  return 0;
}
