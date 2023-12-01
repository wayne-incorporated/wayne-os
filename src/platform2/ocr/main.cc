// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "ocr/daemon.h"

int main(int argc, char* argv[]) {
  brillo::FlagHelper::Init(argc, argv,
                           "ocr_service - Optical Character Recognition "
                           "service.");
  // Always logs to the syslog and logs to stderr if we are
  // connected to a tty.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Run the OCR service.
  VLOG(1) << "ocr_service now starting";
  ocr::OcrDaemon daemon;
  int result = daemon.Run();
  VLOG(1) << "ocr_service stopping with exit code " << result;
  return result;
}
