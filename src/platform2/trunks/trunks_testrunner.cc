// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/test/test_timeouts.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  // Enable verbose logging while running unit tests.
  logging::SetMinLogLevel(logging::LOGGING_VERBOSE);
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  TestTimeouts::Initialize();
  return RUN_ALL_TESTS();
}
