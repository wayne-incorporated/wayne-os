// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "secanomalyd/daemon.h"

int main(int argc, char* argv[]) {
  DEFINE_bool(generate_reports, false, "generate crash reports for anomalies");
  DEFINE_bool(dev, false, "report anomalies when cros_debug=1");
  brillo::FlagHelper::Init(argc, argv,
                           "CrOS security anomaly reporting daemon");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  secanomalyd::Daemon(FLAGS_generate_reports, FLAGS_dev).Run();
  return 0;
}
