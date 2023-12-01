// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cleanup/user_oldest_activity_timestamp_manager.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"
#include "cryptohome/timestamp.pb.h"

namespace cryptohome {

namespace {

base::Time GetTimestampFileData(Platform* platform,
                                const ObfuscatedUsername& obfuscated) {
  brillo::Blob tcontents;
  if (!platform->ReadFile(UserActivityTimestampPath(obfuscated), &tcontents)) {
    return base::Time();
  }

  Timestamp timestamp;
  if (!timestamp.ParseFromArray(tcontents.data(), tcontents.size())) {
    return base::Time();
  }

  return base::Time::FromDeltaSinceWindowsEpoch(
      base::Seconds(timestamp.timestamp()));
}

}  // namespace

UserOldestActivityTimestampManager::UserOldestActivityTimestampManager(
    Platform* platform)
    : platform_(platform) {}

void UserOldestActivityTimestampManager::UpdateCachedTimestamp(
    const ObfuscatedUsername& obfuscated, base::Time timestamp) {
  users_timestamp_lookup_[obfuscated] = timestamp;
}

bool UserOldestActivityTimestampManager::WriteTimestamp(
    const ObfuscatedUsername& obfuscated, base::Time timestamp) {
  Timestamp ts_proto;
  ts_proto.set_timestamp(timestamp.ToDeltaSinceWindowsEpoch().InSeconds());
  std::string timestamp_str;
  if (!ts_proto.SerializeToString(&timestamp_str)) {
    LOG(ERROR) << "Failed to serialize ts: " << ts_proto.timestamp();
    return false;
  }

  base::FilePath ts_file = UserActivityTimestampPath(obfuscated);
  if (!platform_->DirectoryExists(ts_file.DirName())) {
    LOG(ERROR) << "Missing directory for: " << ts_file;
    return false;
  }

  if (!platform_->WriteStringToFileAtomicDurable(ts_file, timestamp_str,
                                                 kKeyFilePermissions)) {
    LOG(ERROR) << "Failed writing to timestamp file: " << ts_file;
    return false;
  }
  return true;
}

// public
void UserOldestActivityTimestampManager::LoadTimestamp(
    const ObfuscatedUsername& obfuscated) {
  const base::Time ts_from_singular_file =
      GetTimestampFileData(platform_, obfuscated);
  UpdateCachedTimestamp(obfuscated, ts_from_singular_file);
}

// TODO(b/205759690, dlunev): can be removed after a stepping stone release.
void UserOldestActivityTimestampManager::LoadTimestampWithLegacy(
    const ObfuscatedUsername& obfuscated, base::Time legacy_timestamp) {
  LoadTimestamp(obfuscated);
  const auto current_timestamp = GetLastUserActivityTimestamp(obfuscated);
  if (legacy_timestamp <= current_timestamp) {
    return;
  }
  if (!WriteTimestamp(obfuscated, legacy_timestamp)) {
    LOG(ERROR) << "Failed to update timestamp for: " << obfuscated;
    return;
  }
  UpdateCachedTimestamp(obfuscated, legacy_timestamp);
  return;
}

bool UserOldestActivityTimestampManager::UpdateTimestamp(
    const ObfuscatedUsername& obfuscated, base::TimeDelta time_shift) {
  base::Time timestamp = platform_->GetCurrentTime();
  if (time_shift > base::TimeDelta()) {
    timestamp -= time_shift;
  }

  if (!WriteTimestamp(obfuscated, timestamp)) {
    LOG(ERROR) << "Failed to update timestamp for: " << obfuscated;
    return false;
  }

  UpdateCachedTimestamp(obfuscated, timestamp);
  return true;
}

void UserOldestActivityTimestampManager::RemoveUser(
    const ObfuscatedUsername& obfuscated) {
  users_timestamp_lookup_.erase(obfuscated);
}

base::Time UserOldestActivityTimestampManager::GetLastUserActivityTimestamp(
    const ObfuscatedUsername& obfuscated) const {
  auto it = users_timestamp_lookup_.find(obfuscated);

  if (it == users_timestamp_lookup_.end()) {
    return base::Time();
  } else {
    return it->second;
  }
}

}  // namespace cryptohome
