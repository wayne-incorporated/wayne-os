// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_RESILIENCE_WRITE_ERROR_TRACKER_H_
#define TRUNKS_RESILIENCE_WRITE_ERROR_TRACKER_H_

#include "trunks/resilience/write_error_tracker.h"

#include <string>

namespace trunks {

class WriteErrorTracker {
 public:
  virtual ~WriteErrorTracker() = default;
  // Records `next_errno` as the most recent error, the return the second recent
  // error.
  virtual int PushError(int next_errno) = 0;
  // Returns if the bad `write()` operation could potentially be fixed by some
  // action.
  // Note: the current only action is to reload the driver. See the pre-start
  // phase in `trunksd.conf`.
  virtual bool ShallTryRecover() = 0;
  // Persists the most recent error in the numeric format to the `file_path`
  // taken by `Initialize()`.
  virtual bool Write() = 0;
};

}  // namespace trunks

#endif  // TRUNKS_RESILIENCE_WRITE_ERROR_TRACKER_H_
