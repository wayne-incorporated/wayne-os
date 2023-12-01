// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_DATA_MIGRATOR_MIGRATION_HELPER_DELEGATE_H_
#define CRYPTOHOME_DATA_MIGRATOR_MIGRATION_HELPER_DELEGATE_H_

#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

#include "cryptohome/data_migrator/metrics.h"

namespace cryptohome::data_migrator {

// The types of the location of files which we failed to migrate.
enum class FailureLocationType {
  // The failure happened in the migration source.
  kSource,
  // The failure happened in the migration destination.
  kDest,
  // The failure happened in the migration source or the destination. This is
  // the case for operations that take both of the source file and the
  // destination file, such as sendfile().
  kSourceOrDest,
};

// Delegate class for MigrationHelper that handles logic specific to the type of
// the migration.
class BRILLO_EXPORT MigrationHelperDelegate {
 public:
  MigrationHelperDelegate() = default;
  virtual ~MigrationHelperDelegate() = default;

  MigrationHelperDelegate(const MigrationHelperDelegate&) = delete;
  MigrationHelperDelegate& operator=(const MigrationHelperDelegate&) = delete;

  // Returns whether MigrationHelper should occasionally report the progress of
  // the migration, which includes the bytes already migrated and the total
  // bytes to be migrated.
  virtual bool ShouldReportProgress() { return true; }

  // Returns true if |path| (relative path from the root directory of the
  // migration source) should be migrated. false means that it will be deleted
  // from the migration source, but not copied to the migration destination.
  virtual bool ShouldMigrateFile(const base::FilePath& path) { return true; }

  // Returns whether MigrationHelper should copy quota project ID.
  virtual bool ShouldCopyQuotaProjectId() = 0;

  // Returns true if MigrationHelper should skip migrating a file when it
  // encounters EIO on opening the file. If this returns true,
  // RecordSkippedFile() is called with the name of the file that failed to open
  // with EIO. Returning false means that the EIO failure causes the entire
  // migration to fail.
  virtual bool ShouldSkipFileOnIOErrors() { return false; }

  // Returns names of xattr to temporarily store mtime/atime of the files during
  // the migration.
  virtual std::string GetMtimeXattrName() = 0;
  virtual std::string GetAtimeXattrName() = 0;

  // Takes metadata of a file, converts it and overwrites it with the result.
  // The result will be used as the metadata of the file copied in the migration
  // destination. Returns true on conversion success. Returning false means that
  // the file will be deleted from the migration source, but not copied to the
  // migration destination.
  virtual bool ConvertFileMetadata(base::stat_wrapper_t* stat) { return true; }

  // Returns the name of xattr in the migration destination that corresponds to
  // the xattr |name| in the migration source.
  virtual std::string ConvertXattrName(const std::string& name) { return name; }

  // Records the name of a file that is skipped during the migration due to file
  // IO error on opening it. |path| is a relative path from migration source.
  virtual void RecordSkippedFile(const base::FilePath& path) {}

  // Returns the amount of free space in bytes that MigrationHelper can use.
  virtual int64_t FreeSpaceForMigrator() = 0;

  // Reports the current time as the migration start time.
  virtual void ReportStartTime() {}
  // Reports the current time as the migration end time.
  virtual void ReportEndTime() {}

  // Reports the migration start status.
  virtual void ReportStartStatus(MigrationStartStatus status) {}
  // Reports the migration end status.
  virtual void ReportEndStatus(MigrationEndStatus status) {}

  // Reports the total bytes in MiB and the total number of files (regular
  // files, directories and symlinks) to be migrated.
  // Called before the migration starts.
  virtual void ReportTotalSize(int total_byte_count_mb, int total_file_count) {}

  // Called when a migration failure happens. Reports the error code, the failed
  // operation type, the relative path to the failed file from the migration
  // root, and the type of the location of the failed file (whether it is in the
  // migration source, the destination, or both).
  virtual void ReportFailure(base::File::Error error_code,
                             MigrationFailedOperationType type,
                             const base::FilePath& child,
                             FailureLocationType location_type) {}

  // Called when ENOSPC failure happens. Reports the amount of free disk space
  // measured before the migration (|initial_migration_free_space_mb|) and at
  // the time of the failure (|failure_free_space_mb|) in MiB.
  virtual void ReportFailedNoSpace(int initial_migration_free_space_mb,
                                   int failure_free_space_mb) {}

  // Called when ENOSPC failure happens when trying to set xattr on a file.
  // Reports in bytes the sum of the total size of xattr already set on a file
  // and the size of an xattr attempted to be set on the file.
  virtual void ReportFailedNoSpaceXattrSizeInBytes(int total_xattr_size_bytes) {
  }
};

}  // namespace cryptohome::data_migrator

#endif  // CRYPTOHOME_DATA_MIGRATOR_MIGRATION_HELPER_DELEGATE_H_
