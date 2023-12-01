// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/lockfile_checker_stub.h"

namespace power_manager::system {

LockfileCheckerStub::LockfileCheckerStub() = default;

LockfileCheckerStub::~LockfileCheckerStub() = default;

std::vector<base::FilePath> LockfileCheckerStub::GetValidLockfiles() const {
  return files_to_return_;
}

}  // namespace power_manager::system
