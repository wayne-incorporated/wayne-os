// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/dircrypto_migration_helper_delegate.h"

#include <string>
#include <vector>

#include <base/logging.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/storage/mount_constants.h"

namespace cryptohome {

namespace {

constexpr char kMtimeXattrName[] = "trusted.CrosDirCryptoMigrationMtime";
constexpr char kAtimeXattrName[] = "trusted.CrosDirCryptoMigrationAtime";
// This lives in root/ of the destination directory so that it is encrypted.
constexpr char kSkippedFileListFileName[] =
    "root/crypto-migration.files-skipped";

// List of paths in the root part of the user home to be migrated when minimal
// migration is performed.
const char* const kMinimalMigrationRootPathsAllowlist[] = {
    // Keep the user policy - network/proxy settings could be stored here and
    // chrome will need network access to re-setup the wiped profile. Also, we
    // want to make absolutely sure that the user session does not end up in an
    // unmanaged state (without policy).
    "session_manager/policy",
};

// List of paths in the user part of the user home to be migrated when minimal
// migration is performed. If the path refers to a directory, all children will
// be migrated too.
const char* const kMinimalMigrationUserPathsAllowlist[] = {
    // Migrate the log directory, because it only gets created on fresh user
    // home creation by copying the skeleton structure. If it's missing, chrome
    // user sessoin won't log.
    "log",
    // Migrate the user's certificate database, in case the user has client
    // certificates necessary to access networks.
    ".pki",
    // Migrate Cookies, as authentiation tokens might be stored in cookies.
    "Cookies",
    "Cookies-journal",
    // Migrate state related to HTTPS, especially channel binding state (Origin
    // Bound Certs), and transport security (HSTS).
    "Origin Bound Certs",
    "Origin Bound Certs-journal",
    "TransportSecurity",
    // Web Data contains the Token Service Table which authentication tokens for
    // chrome services (sign-in OAuth2 token).
    "Web Data",
    "Web Data-journal",
};

struct PathTypeMapping {
  const char* path;
  DircryptoMigrationFailedPathType type;
};

const PathTypeMapping kPathTypeMappings[] = {
    {"root/android-data", kMigrationFailedUnderAndroidOther},
    {"user/Downloads", kMigrationFailedUnderDownloads},
    {"user/Cache", kMigrationFailedUnderCache},
    {"user/GCache", kMigrationFailedUnderGcache},
};

}  // namespace

DircryptoMigrationHelperDelegate::DircryptoMigrationHelperDelegate(
    Platform* platform,
    const base::FilePath& to_dir,
    MigrationType migration_type)
    : platform_(platform),
      to_dir_(to_dir),
      skipped_file_list_path_(to_dir.Append(kSkippedFileListFileName)),
      migration_type_(migration_type) {
  if (migration_type_ == MigrationType::MINIMAL) {
    for (const char* path : kMinimalMigrationRootPathsAllowlist) {
      minimal_migration_paths_.emplace_back(
          base::FilePath(kRootHomeSuffix).Append(path));
    }
    for (const char* path : kMinimalMigrationUserPathsAllowlist) {
      minimal_migration_paths_.emplace_back(
          base::FilePath(kUserHomeSuffix).Append(path));
    }
  }
}

bool DircryptoMigrationHelperDelegate::ShouldReportProgress() {
  // Don't report progress in minimal migration as we're skipping most of data.
  return migration_type_ == MigrationType::FULL;
}

bool DircryptoMigrationHelperDelegate::ShouldMigrateFile(
    const base::FilePath& child) {
  if (migration_type_ == MigrationType::FULL) {
    // crbug.com/728892: This directory can be falling into a weird state that
    // confuses the migrator. Never try migration. Just delete it. This is fine
    // because Cryptohomed anyway creates a pass-through directory at this path
    // and Chrome never uses contents of the directory left by old sessions.
    if (child == base::FilePath(kUserHomeSuffix)
                     .Append(kGCacheDir)
                     .Append(kGCacheVersion1Dir)
                     .Append(kGCacheTmpDir)) {
      return false;
    }

    return true;
  } else {
    // Minimal migration - process the allowlist. Because the allowlist is
    // supposed to be small, we won't recurse into many subdirectories, so we
    // assume that iterating all allowlist elements for each file is fine.
    for (const auto& migration_path : minimal_migration_paths_) {
      // If the current path is one of the allowlisted paths, or its
      // parent, migrate it.
      if (child == migration_path || child.IsParent(migration_path))
        return true;
      // Recursively migrate contents of directories specified for migration.
      if (migration_path.IsParent(child))
        return true;
    }

    return false;
  }
}

bool DircryptoMigrationHelperDelegate::ShouldCopyQuotaProjectId() {
  return false;
}

bool DircryptoMigrationHelperDelegate::ShouldSkipFileOnIOErrors() {
  // b/37444422 causes IO errors when opening this file in some cases. User had
  // an unreadable file, skipping this file means user will no longer have a
  // file but not worse off.
  return true;
}

std::string DircryptoMigrationHelperDelegate::GetMtimeXattrName() {
  return kMtimeXattrName;
}

std::string DircryptoMigrationHelperDelegate::GetAtimeXattrName() {
  return kAtimeXattrName;
}

void DircryptoMigrationHelperDelegate::RecordSkippedFile(
    const base::FilePath& rel_path) {
  base::File skipped_file_list;
  platform_->InitializeFile(
      &skipped_file_list, skipped_file_list_path_,
      base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_APPEND);
  if (!skipped_file_list.IsValid()) {
    PLOG(ERROR) << "Could not open list of skipped files at"
                << skipped_file_list_path_.value() << ", " << rel_path.value()
                << " not added";
    return;
  }
  if (!platform_->LockFile(skipped_file_list.GetPlatformFile())) {
    PLOG(ERROR) << "Failed to lock " << skipped_file_list_path_.value();
    return;
  }
  std::string data = rel_path.value() + "\n";
  int write_size = data.size();
  // O_APPEND was used to open, so write is always done at the end of the file
  // even without seek.
  if (write_size !=
      skipped_file_list.WriteAtCurrentPos(data.data(), write_size)) {
    PLOG(ERROR) << "Failed to write " << rel_path.value()
                << " to the list of skipped files";
    return;
  }
  if (!skipped_file_list.Flush()) {
    PLOG(ERROR) << "Failed to flush " << rel_path.value()
                << " to the list of skipped files";
  }
  if (skipped_file_list.created()) {
    // Sync the parent directory to persist the file.
    if (!platform_->SyncDirectory(skipped_file_list_path_.DirName()))
      PLOG(ERROR) << "Failed to sync parent directory when creating list of "
                     "skipped files "
                  << skipped_file_list_path_.value();
  }
}

int64_t DircryptoMigrationHelperDelegate::FreeSpaceForMigrator() {
  return platform_->AmountOfFreeDiskSpace(to_dir_);
}

void DircryptoMigrationHelperDelegate::ReportStartTime() {
  const auto migration_timer_id = migration_type_ == MigrationType::MINIMAL
                                      ? kDircryptoMinimalMigrationTimer
                                      : kDircryptoMigrationTimer;
  ReportTimerStart(migration_timer_id);
}

void DircryptoMigrationHelperDelegate::ReportEndTime() {
  const auto migration_timer_id = migration_type_ == MigrationType::MINIMAL
                                      ? kDircryptoMinimalMigrationTimer
                                      : kDircryptoMigrationTimer;
  ReportTimerStop(migration_timer_id);
}

void DircryptoMigrationHelperDelegate::ReportStartStatus(
    data_migrator::MigrationStartStatus status) {
  ReportDircryptoMigrationStartStatus(migration_type_, status);
}

void DircryptoMigrationHelperDelegate::ReportEndStatus(
    data_migrator::MigrationEndStatus status) {
  ReportDircryptoMigrationEndStatus(migration_type_, status);
}

void DircryptoMigrationHelperDelegate::ReportFailure(
    base::File::Error error_code,
    data_migrator::MigrationFailedOperationType operation_type,
    const base::FilePath& path,
    data_migrator::FailureLocationType location_type) {
  DircryptoMigrationFailedPathType path_type = kMigrationFailedUnderOther;
  for (const auto& path_type_mapping : kPathTypeMappings) {
    if (base::FilePath(path_type_mapping.path).IsParent(path)) {
      path_type = path_type_mapping.type;
      break;
    }
  }
  // Android cache files are either under
  //   root/android-data/data/data/<package name>/cache
  //   root/android-data/data/media/0/Android/data/<package name>/cache
  if (path_type == kMigrationFailedUnderAndroidOther) {
    std::vector<std::string> components = path.GetComponents();
    if ((components.size() >= 7u && components[2] == "data" &&
         components[3] == "data" && components[5] == "cache") ||
        (components.size() >= 10u && components[2] == "data" &&
         components[3] == "media" && components[4] == "0" &&
         components[5] == "Android" && components[6] == "data" &&
         components[8] == "cache")) {
      path_type = kMigrationFailedUnderAndroidCache;
    }
  }

  ReportDircryptoMigrationFailedOperationType(operation_type);
  ReportDircryptoMigrationFailedPathType(path_type);
  ReportDircryptoMigrationFailedErrorCode(error_code);
}

void DircryptoMigrationHelperDelegate::ReportTotalSize(int total_byte_count_mb,
                                                       int total_file_count) {
  ReportDircryptoMigrationTotalByteCountInMb(total_byte_count_mb);
  ReportDircryptoMigrationTotalFileCount(total_file_count);
}

void DircryptoMigrationHelperDelegate::ReportFailedNoSpace(
    int initial_migration_free_space_mb, int failure_free_space_mb) {
  ReportDircryptoMigrationFailedNoSpace(initial_migration_free_space_mb,
                                        failure_free_space_mb);
}

void DircryptoMigrationHelperDelegate::ReportFailedNoSpaceXattrSizeInBytes(
    int total_xattr_size_bytes) {
  ReportDircryptoMigrationFailedNoSpaceXattrSizeInBytes(total_xattr_size_bytes);
}

}  // namespace cryptohome
