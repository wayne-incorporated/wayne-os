// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <base/logging.h>

#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>

#include "croslog/log_rotator/log_rotator.h"

bool ReloadRsyslog() {
  brillo::ProcessImpl pkill_process;
  pkill_process.AddArg("/sbin/reload");
  pkill_process.AddArg("syslog");
  // Close unused file descriptors in child process.
  pkill_process.SetCloseUnusedFileDescriptors(true);

  // Sends a SIGHUP signal by executing reload command, so that rsyslogd
  // reload the log files and creates new one if the file doesn't exist.
  int exit_code = pkill_process.Run();
  if (exit_code == 0) {
    return true;
  } else {
    const std::string& output = pkill_process.GetOutputString(STDOUT_FILENO);
    LOG(ERROR)
        << "Failed to send a SIGHUP signal to rsyslog. Reload command exited "
        << "with status " << exit_code << ".";
    LOG(ERROR) << "Command Output: " << output;
    return false;
  }
}

int main(int argc, char* argv[]) {
  // Configure the log destination.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  log_rotator::RotateStandardLogFiles();

  if (!ReloadRsyslog())
    return 1;

  return 0;
}
