// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_DATA_MIGRATOR_METRICS_H_
#define ARC_VM_DATA_MIGRATOR_METRICS_H_

#include <memory>

#include <base/files/file.h>
#include <base/time/time.h>
#include <cryptohome/data_migrator/metrics.h>
#include <metrics/metrics_library.h>

namespace arc::data_migrator {

// The result of the setup before triggering MigrationHelper.
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class SetupResult {
  // Migration is successfully set up.
  kSuccess = 0,
  // Failed to mkdir the mount point.
  kMountPointCreationFailure = 1,
  // Failed to attach a loop device to the migration destination.
  kLoopDeviceAttachmentFailure = 2,
  // Failed to call mount().
  kMountFailure = 3,
  // Failed to start a new thread for MigrationHelper.
  kThreadStartFailure = 4,
  // Failed to create /data/media with the casefold flag.
  kDataMediaWithCasefoldSetupFailure = 5,
  kMaxValue = kDataMediaWithCasefoldSetupFailure,
};

// The types of the location of files at which the migration failed. This is a
// product of the location under Android /data (the migration root) and the
// location from the migration tool's perspective (whether the file is in the
// migration source, the destination, or could be both).
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class FailedPathType {
  // Absolute paths that is not under the migration source or the destination.
  kUnknownAbsolutePath = 0,
  // Other
  kOtherSource = 1,
  kOtherDest = 2,
  kOther = 3,
  // Contents under /data/media/0/Android/data.
  kMediaAndroidDataSource = 4,
  kMediaAndroidDataDest = 5,
  kMediaAndroidData = 6,
  // Contents under /data/media/0/Android/obb.
  kMediaAndroidObbSource = 7,
  kMediaAndroidObbDest = 8,
  kMediaAndroidObb = 9,
  // Contents under /data/media/0 excluding /data/media/0/Android/{data,obb}.
  kMediaSource = 10,
  kMediaDest = 11,
  kMedia = 12,
  // Contents under /data/app.
  kAppSource = 13,
  kAppDest = 14,
  kApp = 15,
  // Contents under /data/data.
  kDataSource = 16,
  kDataDest = 17,
  kData = 18,
  // Contents under /data/user/0.
  kUserSource = 19,
  kUserDest = 20,
  kUser = 21,
  // Contents under /data/user_de/0.
  kUserDeSource = 22,
  kUserDeDest = 23,
  kUserDe = 24,
  kMaxValue = kUserDe,
};

// The possible causes of failures for which the error code is
// base::File::FILE_ERROR_ACCESS_DENIED and the error type is
// cryptohome::data_migrator::kMigrationFailedAtOpen*File.
// Keep in sync with ArcVmDataMigrationAccessDeniedAtOpenFileFailureType in
// Chromium's tools/metrics/histograms/enums.xml.
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class AccessDeniedAtOpenFileFailureType {
  kOther = 0,
  kReferencesParent = 1,
  kReferencesParentFalsePositive = 2,
  kPermissionDenied = 3,
  kIsADirectory = 4,
  kReadOnlyFileSystem = 5,
  kOperationNotPermitted = 6,
  kMaxValue = kOperationNotPermitted,
};

// A class that sends UMA metrics using MetricsLibrary. There is no D-Bus call
// because MetricsLibrary writes the UMA data to /var/lib/metrics/uma-events.
class ArcVmDataMigratorMetrics {
 public:
  ArcVmDataMigratorMetrics();
  ~ArcVmDataMigratorMetrics() = default;
  ArcVmDataMigratorMetrics(const ArcVmDataMigratorMetrics&) = delete;
  ArcVmDataMigratorMetrics& operator=(const ArcVmDataMigratorMetrics&) = delete;

  // Reports the duration of the migration.
  void ReportDuration(base::TimeDelta duration);

  // Reports the start and end status of the migration.
  void ReportStartStatus(
      cryptohome::data_migrator::MigrationStartStatus status);
  void ReportEndStatus(cryptohome::data_migrator::MigrationEndStatus status);

  // Reports the total bytes (in MB) and the number of files to be migrated.
  void ReportTotalByteCountInMb(int total_byte_count_mb);
  void ReportTotalFileCount(int total_file_count);

  // Reports the result of the setup before triggering MigrationHelper.
  void ReportSetupResult(SetupResult result);

  // Reports the error code of a failure.
  void ReportFailedErrorCode(base::File::Error error_code);

  // Reports the type of file operation that caused a failure.
  void ReportFailedOperationType(
      cryptohome::data_migrator::MigrationFailedOperationType type);

  // Reports the type of file location at which we failed to migrate.
  void ReportFailedPathType(FailedPathType type);

  // Reports device's free space at the beginning of the migration in MB.
  void ReportInitialFreeSpace(int initial_free_space_mb);

  // Reports device's free space at the timing of ENOSPC failure in MB.
  void ReportNoSpaceFailureFreeSpace(int failure_free_space_mb);

  // Reports the total bytes of xattr assigned to a file.
  void ReportNoSpaceXattrSize(int total_xattr_size_bytes);

  // Reports the detailed cause of b/280247852.
  void ReportAccessDeniedAtOpenSourceFileFailureType(
      AccessDeniedAtOpenFileFailureType failure_type);

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_library_;
};

}  // namespace arc::data_migrator

#endif  // ARC_VM_DATA_MIGRATOR_METRICS_H_
