// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CLOBBER_STATE_COLLECTOR_H_
#define CRASH_REPORTER_CLOBBER_STATE_COLLECTOR_H_

#include <string>

#include <base/files/file_path.h>

#include "crash-reporter/crash_collector.h"

constexpr const char kNoErrorLogged[] = "No error logged.";

// Collect clobber.log which has the error messages that led to the stateful
// clobber.
class ClobberStateCollector : public CrashCollector {
 public:
  ClobberStateCollector();
  ClobberStateCollector(const ClobberStateCollector&) = delete;
  ClobberStateCollector& operator=(const ClobberStateCollector&) = delete;

  ~ClobberStateCollector() override = default;

  bool Collect();

  static CollectorInfo GetHandlerInfo(bool clobber_state);

 protected:
  base::FilePath tmpfiles_log_;
};

#endif  // CRASH_REPORTER_CLOBBER_STATE_COLLECTOR_H_
