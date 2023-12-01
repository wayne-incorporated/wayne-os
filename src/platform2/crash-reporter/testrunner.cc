// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/syslog_logging.h"
#include "common-mk/testrunner.h"

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToStderr);
  brillo::LogToString(true);

  auto runner = platform2::TestRunner(argc, argv);
  return runner.Run();
}
