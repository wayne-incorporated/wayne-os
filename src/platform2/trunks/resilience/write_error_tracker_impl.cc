// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/resilience/write_error_tracker_impl.h"

#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/synchronization/lock.h>
#include <errno.h>

namespace trunks {

WriteErrorTrackerImpl::WriteErrorTrackerImpl(const std::string& last_errno_path)
    : last_errno_path_(last_errno_path) {
  Initialize();
}

int WriteErrorTrackerImpl::PushError(int next_errno) {
  base::AutoLock lock(lock_);
  // Though this method isn't designed for the cases that a write error
  // recovers itself w/o any action, for reliability, assumes it could happen.
  is_from_good_to_bad_once_ |= (previous_errno_ <= 0 && next_errno > 0);
  is_to_another_bad_once_ |=
      (previous_errno_ != next_errno && next_errno > 0 && previous_errno_ > 0);
  const int backup = previous_errno_;
  previous_errno_ = next_errno;
  return backup;
}

bool WriteErrorTrackerImpl::ShallTryRecover() {
  base::AutoLock lock(lock_);
  return previous_errno_ > 0 &&
         (is_from_good_to_bad_once_ || is_to_another_bad_once_);
}

bool WriteErrorTrackerImpl::Write() {
  base::AutoLock lock(lock_);
  const bool ok =
      WriteFile(last_errno_path_, base::NumberToString(previous_errno_));
  if (ok) {
    LOG(INFO) << "Wrote " << previous_errno_ << " to "
              << last_errno_path_.value() << ".";
  } else {
    LOG(WARNING) << "Failed to write errno (" << previous_errno_ << ") to "
                 << last_errno_path_;
  }
  return ok;
}

void WriteErrorTrackerImpl::Initialize() {
  std::string data;
  if (!base::ReadFileToString(last_errno_path_, &data)) {
    if (base::PathExists(last_errno_path_)) {
      LOG(WARNING) << "Can't read " << last_errno_path_.value()
                   << "; proceed as if the file was empty.";
    }
  }
  base::TrimWhitespaceASCII(data, base::TRIM_ALL, &data);
  if (!base::StringToInt(data, &previous_errno_)) {
    LOG_IF(WARNING, !data.empty())
        << "Failed to convert " << data
        << " to integer; proceed as if the previous errno is empty.";
  }
  LOG(INFO) << "Initialized last errno: " << previous_errno_;
}

}  // namespace trunks
