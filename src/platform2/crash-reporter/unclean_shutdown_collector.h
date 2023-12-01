// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The unclean shutdown collector runs on boot (invoked by crash-boot-collect)
// and checks for the existence of a file
// (/var/lib/crash_reporter/pending_clean_shutdown). If it exists, the machine
// was not shut down properly and we increment an UMA metric.
//
// In the normal shutdown flow, the system deletes that file, so its presence in
// early boot indicates that the shutdown was abnormal in some way. This could
// be as simple as the battery dying, which is why we only count occurrences of
// this event rather than collecting logs.

#ifndef CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
#define CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"

// Unclean shutdown collector.
class UncleanShutdownCollector : public CrashCollector {
 public:
  UncleanShutdownCollector();
  UncleanShutdownCollector(const UncleanShutdownCollector&) = delete;
  UncleanShutdownCollector& operator=(const UncleanShutdownCollector&) = delete;

  ~UncleanShutdownCollector() override;

  void set_os_release_for_test(const base::FilePath& os_release) {
    os_release_path_ = os_release;
  }

  // Enable collection - signal that a boot has started.
  bool Enable();

  // Collect if there is was an unclean shutdown. Returns true if
  // there was, false otherwise.
  bool Collect();

  // Disable collection - signal that the system has been shutdown cleanly.
  bool Disable();

  // Save version data from the running OS for collection after an unclean
  // shutdown or kernel crash.
  bool SaveVersionData();

 private:
  friend class UncleanShutdownCollectorTest;
  FRIEND_TEST(UncleanShutdownCollectorTest, EnableCannotWrite);
  FRIEND_TEST(UncleanShutdownCollectorTest, CollectDeadBatterySuspended);

  bool DeleteUncleanShutdownFiles();

  // Check for unclean shutdown due to battery running out by analyzing powerd
  // trace files.
  bool DeadBatteryCausedUncleanShutdown();
  // Check for unclean shutdown
  void LogEcUptime();

  const char* unclean_shutdown_file_;
  base::FilePath powerd_trace_path_;
  base::FilePath powerd_suspended_file_;
  base::FilePath os_release_path_;
};

#endif  // CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
