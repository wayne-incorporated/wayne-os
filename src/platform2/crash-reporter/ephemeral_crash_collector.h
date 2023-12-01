// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The early crash meta collector doesn't collect crashes in the sense that many
// others do. Instead, it moves crashes that happened when the full filesystem
// was not available from ephemeral storage (like /run) to the encrypted
// stateful partition, so that they persist across reboot.

#ifndef CRASH_REPORTER_EPHEMERAL_CRASH_COLLECTOR_H_
#define CRASH_REPORTER_EPHEMERAL_CRASH_COLLECTOR_H_

#include <vector>

#include <base/files/file_path.h>

#include "crash-reporter/crash_collector.h"

// The ephemeral crash collector persists already collected crashes into the
// either the encrypted stateful partition or (in its absence) the encrypted
// reboot vault.
class EphemeralCrashCollector : public CrashCollector {
 public:
  EphemeralCrashCollector();
  EphemeralCrashCollector(const EphemeralCrashCollector&) = delete;
  EphemeralCrashCollector& operator=(const EphemeralCrashCollector&) = delete;

  ~EphemeralCrashCollector() override = default;

  void Initialize(bool preserve_across_clobber);

  // True iff we should run the collector even without metrics consent.
  // (The consent file may not be available after a clobber or a powerwash that
  // happened after a mount failure).
  // We'll defer to crash_sender on these crashes.
  bool SkipConsent() { return skip_consent_; }

  // Collect early crashes collected into /run/crash_reporter/crash
  bool Collect();

 private:
  bool early_;
  bool skip_consent_ = false;
  std::vector<base::FilePath> source_directories_;
  friend class EphemeralCrashCollectorTest;
};

#endif  // CRASH_REPORTER_EPHEMERAL_CRASH_COLLECTOR_H_
