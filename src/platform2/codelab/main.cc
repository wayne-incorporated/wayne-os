// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "codelab/codelab.h"

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

int main(int argc, char** argv) {
  DEFINE_bool(quiet, false, "Suppress console output.");

  brillo::FlagHelper::Init(argc, argv, argv[0]);
  if (FLAGS_quiet) {
    brillo::InitLog(brillo::kLogToSyslog);
  } else {
    brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  }

  LOG(INFO) << "Hello from ChromeOS! Gimme " << codelab::GiveFive();
  return 0;
}
