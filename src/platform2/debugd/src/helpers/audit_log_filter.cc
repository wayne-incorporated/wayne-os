// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Outputs processed audit events.
// Internally calls ausearch command and processes its output by filtering out
// tokens that shouldn't be included in a CrOS feedback report.

#include <unistd.h>

#include <iostream>
#include <string>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>

#include "debugd/src/helpers/audit_log_utils.h"

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToStderr);

  if (argc != 1) {
    LOG(ERROR) << "audit_log_filter takes no arguements.";
    return EXIT_FAILURE;
  }

  brillo::ProcessImpl p;
  p.AddArg("/sbin/ausearch");
  p.AddArg("--interpret");
  p.AddStringOption("--start", "today");
  p.AddStringOption("--message", "AVC,SYSCALL");
  p.RedirectUsingPipe(STDOUT_FILENO, false /* is_input */);

  if (!p.Start()) {
    LOG(ERROR) << "Failed to start ausearch.";
    return EXIT_FAILURE;
  }

  base::ScopedFD fd(p.GetPipe(STDOUT_FILENO));
  FILE* file = fdopen(fd.get(), "r");
  if (!file) {
    PLOG(ERROR) << "fdopen failed";
    return EXIT_FAILURE;
  }

  char* buffer = NULL;
  size_t buffer_len = 0;
  while (getline(&buffer, &buffer_len, file) >= 0) {
    std::cout << debugd::FilterAuditLine(buffer) << std::endl;
  }

  if (p.Wait() != 0) {
    LOG(WARNING) << "Failed to wait ausearch.";
  }

  // We're leaking resources on purpose since the kernel will release
  // everything for us.
  return EXIT_SUCCESS;
}
