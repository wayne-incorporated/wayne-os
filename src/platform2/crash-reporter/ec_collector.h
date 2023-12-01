// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The EC collector runs just after boot and grabs information about crashes in
// the Embedded Controller from /sys/kernel/debug/cros_ec/panicinfo.
// For details on this controller, see:
// https://chromium.googlesource.com/chromiumos/platform/ec/+/HEAD/README.md
// The EC collector runs via the crash-boot-collect service.

#ifndef CRASH_REPORTER_EC_COLLECTOR_H_
#define CRASH_REPORTER_EC_COLLECTOR_H_

#include <base/files/file_path.h>

#include "crash-reporter/crash_collector.h"

/* From ec/include/panic.h */
/* Byte [2] of panicinfo contains flags */
#define PANIC_DATA_FLAGS_BYTE 2
/* Set to 1 if already returned via host command */
#define PANIC_DATA_FLAG_OLD_HOSTCMD (1 << 2)

// EC crash collector.
class ECCollector : public CrashCollector {
 public:
  ECCollector();
  ECCollector(const ECCollector&) = delete;
  ECCollector& operator=(const ECCollector&) = delete;

  ~ECCollector() override;

  // Collect any preserved EC panicinfo. Returns true if there was
  // a valid dump (even if there were problems storing the dump), false
  // otherwise.
  bool Collect(bool use_saved_lsb);

 private:
  friend class ECCollectorTest;

  base::FilePath debugfs_path_;
};

#endif  // CRASH_REPORTER_EC_COLLECTOR_H_
