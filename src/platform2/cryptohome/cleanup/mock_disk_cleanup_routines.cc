// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cleanup/mock_disk_cleanup_routines.h"

namespace cryptohome {

MockDiskCleanupRoutines::MockDiskCleanupRoutines()
    : DiskCleanupRoutines(nullptr, nullptr) {}
MockDiskCleanupRoutines::~MockDiskCleanupRoutines() = default;

}  // namespace cryptohome
