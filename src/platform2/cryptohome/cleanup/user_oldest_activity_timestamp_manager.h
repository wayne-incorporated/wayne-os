// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CLEANUP_USER_OLDEST_ACTIVITY_TIMESTAMP_MANAGER_H_
#define CRYPTOHOME_CLEANUP_USER_OLDEST_ACTIVITY_TIMESTAMP_MANAGER_H_

#include <map>
#include <string>

#include <base/time/time.h>

#include "cryptohome/platform.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Manages last access timestamp for users.
class UserOldestActivityTimestampManager {
 public:
  explicit UserOldestActivityTimestampManager(Platform* platform);
  UserOldestActivityTimestampManager(
      const UserOldestActivityTimestampManager&) = delete;
  UserOldestActivityTimestampManager& operator=(
      const UserOldestActivityTimestampManager&) = delete;

  virtual ~UserOldestActivityTimestampManager() = default;

  // TODO(b/205759690, dlunev): can be removed after a stepping stone release.
  virtual void LoadTimestampWithLegacy(const ObfuscatedUsername& obfuscated,
                                       base::Time legacy_timestamp);

  // Loads timestamp from the per-user timestamp file into cache.
  virtual void LoadTimestamp(const ObfuscatedUsername& obfuscated);

  // Updates on per-user timestamp file and cache. Returns false if updating
  // failed.
  virtual bool UpdateTimestamp(const ObfuscatedUsername& obfuscated,
                               base::TimeDelta time_shift);

  // Remove a user from the cache.
  virtual void RemoveUser(const ObfuscatedUsername& obfuscated);

  // Returns the last activity timestamp for a user. For users without a
  // timestamp it returns a NULL time.
  virtual base::Time GetLastUserActivityTimestamp(
      const ObfuscatedUsername& obfuscated) const;

 private:
  // Updates the cached timestamp.
  void UpdateCachedTimestamp(const ObfuscatedUsername& obfuscated,
                             base::Time timestamp);

  // Updates per-user timestamp file. Returns false if write failed.
  bool WriteTimestamp(const ObfuscatedUsername& obfuscated,
                      base::Time timestamp);

  Platform* platform_;
  std::map<ObfuscatedUsername, base::Time> users_timestamp_lookup_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CLEANUP_USER_OLDEST_ACTIVITY_TIMESTAMP_MANAGER_H_
