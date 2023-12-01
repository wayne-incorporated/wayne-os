// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/syslog_logging.h>

#include "rgbkbd/rgbkbd_daemon.h"

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  LOG(INFO) << "Starting Chrome OS RGB Keyboard Daemon";

  auto result = rgbkbd::RgbkbdDaemon().Run();
  if (result == 0) {
    LOG(INFO) << "Chrome OS RGB Keyboard Daemon exited successfully";
  } else {
    LOG(ERROR) << "Exiting Chrome OS RGB Keyboard Daemon with error code "
               << result;
  }
  return result;
}
