// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "faced/face_auth_daemon.h"

int main(int argc, char** argv) {
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");

  brillo::FlagHelper::Init(argc, argv, "Face Authentication Service");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetMinLogLevel(FLAGS_log_level);

  LOG(INFO) << "Starting service...";
  faced::FaceAuthDaemon daemon;
  const int ret = daemon.Run();
  LOG(INFO) << "Service stopped with exit code " << ret;
  return ret;
}
