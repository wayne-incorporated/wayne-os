// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The crash reporter failure collector attempts to report crashes in
// crash_reporter that occur while it's processing a crash.
// In linux, if the program in /proc/sys/kernel/core_pattern crashes after being
// invoked, the kernel logs a special message and does NOT re-invoke the
// program. anomaly_detector picks up that message in logs and invokes
// crash_reporter (which runs this collector and hopefully doesn't crash again).

#ifndef CRASH_REPORTER_CRASH_REPORTER_FAILURE_COLLECTOR_H_
#define CRASH_REPORTER_CRASH_REPORTER_FAILURE_COLLECTOR_H_

#include "crash-reporter/crash_collector.h"

// Collector to record crash_reportor itself crashing.
class CrashReporterFailureCollector : public CrashCollector {
 public:
  CrashReporterFailureCollector();
  CrashReporterFailureCollector(const CrashReporterFailureCollector&) = delete;
  CrashReporterFailureCollector& operator=(
      const CrashReporterFailureCollector&) = delete;

  ~CrashReporterFailureCollector() override;

  // Collect crash reporter failures.
  bool Collect();

  static CollectorInfo GetHandlerInfo(bool crash_reporter_crashed);
};

#endif  // CRASH_REPORTER_CRASH_REPORTER_FAILURE_COLLECTOR_H_
