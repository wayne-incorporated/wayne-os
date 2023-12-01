// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "diagnostics/wilco_dtc_supportd/daemon.h"

int main(int argc, char** argv) {
  brillo::FlagHelper::Init(
      argc, argv, "wilco_dtc_supportd - Support daemon for wilco_dtc.");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  return diagnostics::wilco::Daemon().Run();
}
