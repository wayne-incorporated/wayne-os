// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_paths.h"

#include <base/logging.h>

namespace paths {
namespace {
// Chrome's crash report log file when not under the dry run mode.
constexpr char kChromeCrashLog[] = "/var/log/chrome/Crash Reports/uploads.log";
}  // namespace

// static
bool ChromeCrashLog::dry_run_ = false;

// static
void ChromeCrashLog::SetDryRun(bool enable) {
  dry_run_ = enable;
}

// static
const char* ChromeCrashLog::Get() {
  if (dry_run_) {
    LOG(ERROR) << "Attempted to access uploads.log under the dry run mode.";
    return "/dev/full";  // Write to this file will always fail.
  } else {
    return kChromeCrashLog;
  }
}
}  // namespace paths
