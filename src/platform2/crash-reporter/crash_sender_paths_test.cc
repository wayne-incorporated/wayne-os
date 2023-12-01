// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_paths.h"

#include <gtest/gtest.h>

namespace paths {
namespace {
// Chrome's crash report log file when not under the dry run mode.
constexpr char kChromeCrashLog[] = "/var/log/chrome/Crash Reports/uploads.log";

TEST(CrashSenderPathsTest, ChromeCrashLog) {
  // Default is not under the dry run mode.
  EXPECT_STREQ(kChromeCrashLog, ChromeCrashLog::Get());

  // Switch dry run mode on.
  ChromeCrashLog::SetDryRun(true);
  EXPECT_STREQ("/dev/full", ChromeCrashLog::Get());

  // Switch dry run mode back off.
  ChromeCrashLog::SetDryRun(false);
  EXPECT_STREQ(kChromeCrashLog, ChromeCrashLog::Get());
}
}  // namespace
}  // namespace paths
