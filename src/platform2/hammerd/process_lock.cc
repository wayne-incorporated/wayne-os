// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hammerd/process_lock.h"

#include <sys/file.h>

#include <utility>

#include <base/logging.h>

namespace hammerd {

ProcessLock::ProcessLock(const base::FilePath& lock_file)
    : lock_file_(lock_file) {}

ProcessLock::~ProcessLock() {
  Release();
}

bool ProcessLock::IsLocked() const {
  return fd_.is_valid();
}

bool ProcessLock::Acquire() {
  if (IsLocked()) {
    return true;
  }

  base::ScopedFD fd(
      open(lock_file_.value().c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0666));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open the file";
    return false;
  }
  if (flock(fd.get(), LOCK_EX | LOCK_NB) != 0) {
    PLOG(ERROR) << "Failed to lock the file";
    return false;
  }
  LOG(INFO) << "Locked the file";
  fd_ = std::move(fd);
  return true;
}

bool ProcessLock::Release() {
  if (!IsLocked()) {
    return true;
  }

  if (flock(fd_.get(), LOCK_UN | LOCK_NB) != 0) {
    PLOG(ERROR) << "Failed to unlock the file";
    return false;
  }
  LOG(INFO) << "Unlocked the file";
  fd_.reset();
  return true;
}
}  // namespace hammerd
