// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_RESILIENCE_WRITE_ERROR_TRACKER_IMPL_H_
#define TRUNKS_RESILIENCE_WRITE_ERROR_TRACKER_IMPL_H_

#include "trunks/resilience/write_error_tracker.h"

#include <string>

#include <base/files/file_path.h>
#include <base/synchronization/lock.h>

namespace trunks {

class WriteErrorTrackerImpl : public WriteErrorTracker {
 public:
  explicit WriteErrorTrackerImpl(const std::string& last_errno_path);
  ~WriteErrorTrackerImpl() override = default;
  WriteErrorTrackerImpl(const WriteErrorTrackerImpl&) = delete;
  WriteErrorTrackerImpl(WriteErrorTrackerImpl&&) = delete;
  int PushError(int next_errno) override;
  bool ShallTryRecover() override;
  bool Write() override;

 private:
  // Set `previous_errno_` by reading the content in `last_errno_path_`;
  // designed to be called by constructor.
  void Initialize();

  // The sindle lock that enforces single-threaded access to all members in this
  // class at once.
  base::Lock lock_;
  // The file used to record the error from the previous or current process
  // cycle.
  const base::FilePath last_errno_path_;
  int previous_errno_ = 0;
  bool is_from_good_to_bad_once_ = false;
  bool is_to_another_bad_once_ = false;
};

}  // namespace trunks

#endif  // TRUNKS_RESILIENCE_WRITE_ERROR_TRACKER_IMPL_H_
