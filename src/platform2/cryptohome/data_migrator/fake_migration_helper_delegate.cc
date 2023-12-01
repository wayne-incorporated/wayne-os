// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/data_migrator/fake_migration_helper_delegate.h"

#include <string>

#include <base/containers/contains.h>
#include <base/files/file_path.h>

#include "cryptohome/platform.h"

namespace cryptohome::data_migrator {

namespace {

constexpr char kMtimeXattrName[] = "user.mtime";
constexpr char kAtimeXattrName[] = "user.atime";

}  // namespace

FakeMigrationHelperDelegate::FakeMigrationHelperDelegate(
    Platform* platform, const base::FilePath& to_dir)
    : platform_(platform), to_dir_(to_dir) {}

FakeMigrationHelperDelegate::~FakeMigrationHelperDelegate() = default;

void FakeMigrationHelperDelegate::AddDenylistedPath(
    const base::FilePath& path) {
  denylisted_paths_.insert(path);
}

void FakeMigrationHelperDelegate::AddXattrMapping(const std::string& name_from,
                                                  const std::string& name_to) {
  xattr_mappings_[name_from] = name_to;
}

void FakeMigrationHelperDelegate::AddUidMapping(
    uid_t uid_from, const std::optional<uid_t>& uid_to) {
  uid_mappings_[uid_from] = uid_to;
}

void FakeMigrationHelperDelegate::SetFreeDiskSpaceForMigrator(
    int64_t free_disk_space_for_migrator) {
  free_disk_space_for_migrator_ = free_disk_space_for_migrator;
}

bool FakeMigrationHelperDelegate::ShouldMigrateFile(
    const base::FilePath& child) {
  return !base::Contains(denylisted_paths_, child);
}

bool FakeMigrationHelperDelegate::ShouldCopyQuotaProjectId() {
  return true;
}

bool FakeMigrationHelperDelegate::ShouldSkipFileOnIOErrors() {
  return true;
}

std::string FakeMigrationHelperDelegate::GetMtimeXattrName() {
  return kMtimeXattrName;
}

std::string FakeMigrationHelperDelegate::GetAtimeXattrName() {
  return kAtimeXattrName;
}

bool FakeMigrationHelperDelegate::ConvertFileMetadata(
    base::stat_wrapper_t* stat) {
  auto iter = uid_mappings_.find(stat->st_uid);
  if (iter != uid_mappings_.end()) {
    if (iter->second.has_value()) {
      stat->st_uid = iter->second.value();
      return true;
    }
    return false;
  }
  return true;
}

std::string FakeMigrationHelperDelegate::ConvertXattrName(
    const std::string& name) {
  auto iter = xattr_mappings_.find(name);
  if (iter != xattr_mappings_.end()) {
    return iter->second;
  }
  return name;
}

int64_t FakeMigrationHelperDelegate::FreeSpaceForMigrator() {
  if (free_disk_space_for_migrator_.has_value()) {
    return free_disk_space_for_migrator_.value();
  }
  return platform_->AmountOfFreeDiskSpace(to_dir_);
}

}  // namespace cryptohome::data_migrator
