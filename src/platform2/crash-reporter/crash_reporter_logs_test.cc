// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>
#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

namespace {

// Name of the checked-in configuration file containing log-collection commands.
const char kLogConfigFileName[] = "crash_reporter_logs.conf";

// Executable name for Chrome. kLogConfigFileName is expected to contain
// this entry.
const char kChromeExecName[] = "chrome";

}  // namespace

// Tests that the config file is parsable and that Chrome is listed.
TEST(CrashReporterLogsTest, ReadConfig) {
  brillo::KeyValueStore store;
  ASSERT_TRUE(store.Load(
      test_util::GetTestDataPath(kLogConfigFileName, /*use_testdata=*/false)));
  std::string command;
  EXPECT_TRUE(store.GetString(kChromeExecName, &command));
  EXPECT_FALSE(command.empty());
}

// Verify that all entries are valid shell.
TEST(CrashReporterLogsTest, ValidShell) {
  brillo::KeyValueStore store;
  ASSERT_TRUE(store.Load(
      test_util::GetTestDataPath(kLogConfigFileName, /*use_testdata=*/false)));

  for (const auto& key : store.GetKeys()) {
    std::string command;
    ASSERT_TRUE(store.GetString(key, &command));
    brillo::ProcessImpl diag_process;
    diag_process.AddArg("/bin/sh");
    diag_process.AddArg("-n");
    // While bash supports `-n -c ...` as one expects, dash ignores -n and tries
    // to actually execute the command.  Both respect -n when using stdin.
    diag_process.RedirectUsingPipe(STDIN_FILENO, true);
    ASSERT_TRUE(diag_process.Start());
    int stdin_fd = diag_process.GetPipe(STDIN_FILENO);
    ASSERT_TRUE(base::WriteFileDescriptor(stdin_fd, command));
    ASSERT_GE(close(stdin_fd), 0);
    EXPECT_EQ(0, diag_process.Wait());
  }
}
