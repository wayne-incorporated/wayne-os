// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>

#include "debugd/src/constants.h"

namespace {

const char kUsageMessage[] =
    "\n"
    "Configures Chrome remote debugging on port 9222."
    "\n";

bool IsConfigured() {
  return base::PathExists(
      base::FilePath(debugd::kDevFeaturesChromeRemoteDebuggingFlagPath));
}

bool ConfigureChromeRemoteDebugging() {
  bool result = true;
  if (IsConfigured()) {
    VLOG(1) << "Chrome remote debugging is already on.";
  } else {
    // This is basically touching a new empty file.  It's only checked for
    // existence.  The content is not used.
    int bytes_written = base::WriteFile(
        base::FilePath(debugd::kDevFeaturesChromeRemoteDebuggingFlagPath), "",
        0);
    if (bytes_written < 0) {
      PLOG(WARNING) << "Failed to write Chrome remote debugging marker file.";
      result = false;
    }
  }
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(q, false,
              "Query whether Chrome remote debugging has been configured");
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  if (FLAGS_q) {
    return IsConfigured() ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  return ConfigureChromeRemoteDebugging() ? EXIT_SUCCESS : EXIT_FAILURE;
}
