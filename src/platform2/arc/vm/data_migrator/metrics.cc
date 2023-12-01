// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/metrics.h"

#include <base/numerics/safe_conversions.h>

using cryptohome::data_migrator::MigrationEndStatus;
using cryptohome::data_migrator::MigrationFailedOperationType;
using cryptohome::data_migrator::MigrationStartStatus;

namespace arc::data_migrator {

namespace {

constexpr char kDuration[] = "Arc.VmDataMigration.Duration";
constexpr char kStartStatus[] = "Arc.VmDataMigration.StartStatus";
constexpr char kEndStatus[] = "Arc.VmDataMigration.EndStatus";
constexpr char kTotalSizeMb[] = "Arc.VmDataMigration.TotalSizeMB";
constexpr char kTotalFileCount[] = "Arc.VmDataMigration.TotalFiles";
constexpr char kSetupResult[] = "Arc.VmDataMigration.SetupResult";
constexpr char kFailedErrorCode[] = "Arc.VmDataMigration.FailedErrorCode";
constexpr char kFailedOperationType[] =
    "Arc.VmDataMigration.FailedOperationType";
constexpr char kFailedPathType[] = "Arc.VmDataMigration.FailedPathType";
constexpr char kInitialFreeSpace[] = "Arc.VmDataMigration.InitialFreeSpace";
constexpr char kNoSpaceFailureFreeSpace[] =
    "Arc.VmDataMigration.NoSpaceFailureFreeSpace";
constexpr char kNoSpaceFailureXattrSize[] =
    "Arc.VmDataMigration.NoSpaceFailureXattrSize";
constexpr char kAccessDeniedAtOpenSourceFileFailureType[] =
    "Arc.VmDataMigration.AccessDeniedAtOpenSourceFileFailureType";

constexpr int kNumBuckets = 50;

}  // namespace

ArcVmDataMigratorMetrics::ArcVmDataMigratorMetrics()
    : metrics_library_(std::make_unique<MetricsLibrary>()) {}

void ArcVmDataMigratorMetrics::ReportDuration(base::TimeDelta duration) {
  constexpr int kMin = 1, kMax = 3600 /* 1 hour */;
  metrics_library_->SendToUMA(kDuration,
                              base::saturated_cast<int>(duration.InSeconds()),
                              kMin, kMax, kNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportStartStatus(MigrationStartStatus status) {
  metrics_library_->SendEnumToUMA(
      kStartStatus, static_cast<int>(status),
      static_cast<int>(MigrationStartStatus::kMigrationStartStatusNumBuckets));
}

void ArcVmDataMigratorMetrics::ReportEndStatus(MigrationEndStatus status) {
  metrics_library_->SendEnumToUMA(
      kEndStatus, static_cast<int>(status),
      static_cast<int>(MigrationEndStatus::kMigrationEndStatusNumBuckets));
}

void ArcVmDataMigratorMetrics::ReportTotalByteCountInMb(
    int total_byte_count_mb) {
  constexpr int kMin = 1, kMax = 64 * 1024 /* 64 GiB */;
  metrics_library_->SendToUMA(kTotalSizeMb, total_byte_count_mb, kMin, kMax,
                              kNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportTotalFileCount(int total_file_count) {
  constexpr int kMin = 1, kMax = 200000 /* 200K files */;
  metrics_library_->SendToUMA(kTotalFileCount, total_file_count, kMin, kMax,
                              kNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportSetupResult(SetupResult result) {
  metrics_library_->SendEnumToUMA(kSetupResult, result);
}

void ArcVmDataMigratorMetrics::ReportFailedErrorCode(
    base::File::Error error_code) {
  // Negate |error_code| since it's a non-positive integer.
  metrics_library_->SendEnumToUMA(kFailedErrorCode, -error_code,
                                  -base::File::FILE_ERROR_MAX);
}

void ArcVmDataMigratorMetrics::ReportFailedOperationType(
    cryptohome::data_migrator::MigrationFailedOperationType type) {
  metrics_library_->SendEnumToUMA(
      kFailedOperationType, type,
      cryptohome::data_migrator::kMigrationFailedOperationTypeNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportFailedPathType(FailedPathType type) {
  metrics_library_->SendEnumToUMA(kFailedPathType, type);
}

void ArcVmDataMigratorMetrics::ReportInitialFreeSpace(
    int initial_free_space_mb) {
  constexpr int kMin = 1, kMax = 128 * 1024 /* 128 GiB */;
  metrics_library_->SendToUMA(kInitialFreeSpace, initial_free_space_mb, kMin,
                              kMax, kNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportNoSpaceFailureFreeSpace(
    int failure_free_space_mb) {
  constexpr int kMin = 1, kMax = 128 * 1024 /* 128 GiB */;
  metrics_library_->SendToUMA(kNoSpaceFailureFreeSpace, failure_free_space_mb,
                              kMin, kMax, kNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportNoSpaceXattrSize(
    int total_xattr_size_bytes) {
  constexpr int kMin = 1, kMax = 16 * 1024 /* 16 KiB */;
  metrics_library_->SendToUMA(kNoSpaceFailureXattrSize, total_xattr_size_bytes,
                              kMin, kMax, kNumBuckets);
}

void ArcVmDataMigratorMetrics::ReportAccessDeniedAtOpenSourceFileFailureType(
    AccessDeniedAtOpenFileFailureType failure_type) {
  metrics_library_->SendEnumToUMA(kAccessDeniedAtOpenSourceFileFailureType,
                                  failure_type);
}

}  // namespace arc::data_migrator
