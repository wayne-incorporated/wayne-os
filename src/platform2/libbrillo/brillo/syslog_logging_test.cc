// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>

namespace brillo {

class SyslogLoggingDeathTest : public ::testing::Test {
 public:
  SyslogLoggingDeathTest() {}
  SyslogLoggingDeathTest(const SyslogLoggingDeathTest&) = delete;
  SyslogLoggingDeathTest& operator=(const SyslogLoggingDeathTest&) = delete;

  virtual ~SyslogLoggingDeathTest() {}
};

TEST_F(SyslogLoggingDeathTest, FatalLoggingIsFatal) {
  int old_flags = GetLogFlags();
  SetLogFlags(kLogToStderr);
  EXPECT_DEATH({ LOG(FATAL) << "First Fatality!"; }, "First Fatality!");
  // No flags == don't log to syslog, stderr, or accumulated string.
  SetLogFlags(0);
  // Still a fatal log message
  EXPECT_DEATH({ LOG(FATAL) << "Second Fatality!"; }, "Second Fatality!");
  SetLogFlags(old_flags);
}

}  // namespace brillo
