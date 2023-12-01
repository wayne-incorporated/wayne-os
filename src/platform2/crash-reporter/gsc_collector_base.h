// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The GSC collector runs just after boot and grabs information about crashes in
// the Google Security Chip from `gsctool`.
// The GSC collector runs via the crash-boot-collect service.

#ifndef CRASH_REPORTER_GSC_COLLECTOR_BASE_H_
#define CRASH_REPORTER_GSC_COLLECTOR_BASE_H_

#include <string>

#include "crash-reporter/crash_collector.h"

// GSC Crash Collector Interface
class GscCollectorBase : public CrashCollector {
 public:
  GscCollectorBase();
  GscCollectorBase(const GscCollectorBase&) = delete;
  GscCollectorBase& operator=(const GscCollectorBase&) = delete;

  ~GscCollectorBase() override = default;

  enum class Status {
    Success,
    Fail,
  };

  // Collect any preserved GSC crash data. Returns true if there was
  // a dump (even if there were problems storing the dump), false otherwise.
  bool Collect(bool use_saved_lsb);

  virtual Status PersistGscCrashId(uint32_t crash_id);

 private:
  virtual Status GetGscFlog(std::string* flog_output) = 0;
  Status ParseGscFlog(const std::string& gsctool_flog);
  Status GetCrashId(const std::string& flog_line, uint32_t* crash_id);
  Status GetPreviousGscCrashId(uint32_t* crash_id);

  bool crash_detected_;
  // The latest crash ID in the current GSC flog output.
  uint32_t latest_crash_id_;
  // The GSC crash ID of the last crash report.
  uint32_t prev_crash_id_;
};

#endif  // CRASH_REPORTER_GSC_COLLECTOR_BASE_H_
