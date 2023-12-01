// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CLEANUP_MOCK_DISK_CLEANUP_ROUTINES_H_
#define CRYPTOHOME_CLEANUP_MOCK_DISK_CLEANUP_ROUTINES_H_

#include "cryptohome/cleanup/disk_cleanup_routines.h"

#include <string>

#include <gmock/gmock.h>

namespace cryptohome {

class MockDiskCleanupRoutines : public DiskCleanupRoutines {
 public:
  MockDiskCleanupRoutines();
  virtual ~MockDiskCleanupRoutines();

  MOCK_METHOD(bool, DeleteUserCache, (const ObfuscatedUsername&), (override));
  MOCK_METHOD(bool, DeleteUserGCache, (const ObfuscatedUsername&), (override));
  MOCK_METHOD(bool, DeleteCacheVault, (const ObfuscatedUsername&), (override));
  MOCK_METHOD(bool,
              DeleteUserAndroidCache,
              (const ObfuscatedUsername&),
              (override));
  MOCK_METHOD(bool, DeleteUserProfile, (const ObfuscatedUsername&), (override));
};
}  // namespace cryptohome

#endif  // CRYPTOHOME_CLEANUP_MOCK_DISK_CLEANUP_ROUTINES_H_
