// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_DATA_MIGRATOR_METRICS_H_
#define CRYPTOHOME_DATA_MIGRATOR_METRICS_H_

namespace cryptohome::data_migrator {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum MigrationStartStatus {
  kMigrationStarted = 1,
  kMigrationResumed = 2,
  kMigrationStartStatusNumBuckets
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum MigrationEndStatus {
  kNewMigrationFailedGeneric = 1,
  kNewMigrationFinished = 2,
  kResumedMigrationFailedGeneric = 3,
  kResumedMigrationFinished = 4,
  kNewMigrationFailedLowDiskSpace = 5,
  kResumedMigrationFailedLowDiskSpace = 6,
  // The detail of the "FileError" failures (the failed file operation,
  // error code, and the rough classification of the failed path) will be
  // reported in separate metrics, too. Since there's no good way to relate the
  // multi-dimensional metric however, we treat some combinations as special
  // cases and distinguish them here as well.
  kNewMigrationFailedFileError = 7,
  kResumedMigrationFailedFileError = 8,
  kNewMigrationFailedFileErrorOpenEIO = 9,
  kResumedMigrationFailedFileErrorOpenEIO = 10,
  kNewMigrationCancelled = 11,
  kResumedMigrationCancelled = 12,
  kNewMigrationFailedENOSPC = 13,
  kResumedMigrationFailedENOSPC = 14,
  kMigrationEndStatusNumBuckets
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum MigrationFailedOperationType {
  kMigrationFailedAtOtherOperation = 1,
  kMigrationFailedAtOpenSourceFile = 2,
  kMigrationFailedAtOpenDestinationFile = 3,
  kMigrationFailedAtCreateLink = 4,
  kMigrationFailedAtDelete = 5,
  kMigrationFailedAtGetAttribute = 6,
  kMigrationFailedAtMkdir = 7,
  kMigrationFailedAtReadLink = 8,
  kMigrationFailedAtSeek = 9,
  kMigrationFailedAtSendfile = 10,
  kMigrationFailedAtSetAttribute = 11,
  kMigrationFailedAtStat = 12,
  kMigrationFailedAtSync = 13,
  kMigrationFailedAtTruncate = 14,
  kMigrationFailedAtOpenSourceFileNonFatal = 15,
  kMigrationFailedAtRemoveAttribute = 16,
  kMigrationFailedOperationTypeNumBuckets
};

}  // namespace cryptohome::data_migrator

#endif  // CRYPTOHOME_DATA_MIGRATOR_METRICS_H_
