// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CRASH_SENDER_PATHS_H_
#define CRASH_REPORTER_CRASH_SENDER_PATHS_H_

namespace paths {

// File whose existence mocks crash sending.  If empty we pretend the
// crash sending was successful, otherwise unsuccessful.
constexpr char kMockCrashSending[] = "mock-crash-sending";

// File whose existence causes crash sending to be delayed (for testing).
// Must be stateful to enable testing kernel crashes.
constexpr char kPauseCrashSending[] = "/var/lib/crash_sender_paused";

// Directory where crash_sender stores timestamp files, that indicate the
// upload attempts in the past 24 hours.
constexpr char kTimestampsDirectory[] = "/var/lib/crash_sender";

// Directory where crash_sender stores other state information (ex. client ID).
constexpr char kCrashSenderStateDirectory[] = "/var/lib/crash_sender/state";

// File indicating that crash-sender ran and finished (only used during
// integration test or mock runs).
// MUST MATCH sender_login.go in tast-tests repo.
constexpr char kCrashSenderDone[] = "crash-sender-done";

// Manages the paths to Chrome's crash report log file. Forbids access to
// uploads.log under the dry run mode: crash_sender under the dry run mode
// should not write to any files under /var/log other than /var/log/messages.
class ChromeCrashLog {
 public:
  // This class contains static methods only.
  ChromeCrashLog() = delete;

  // Sets or unsets dry run mode.
  static void SetDryRun(bool enable);
  // Gets the path to the crash log.
  static const char* Get();

 private:
  // Whether crash_sender is under the dry run mode.
  static bool dry_run_;
};

}  // namespace paths

#endif  // CRASH_REPORTER_CRASH_SENDER_PATHS_H_
