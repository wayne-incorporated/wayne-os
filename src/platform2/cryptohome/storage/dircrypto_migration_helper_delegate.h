// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_DIRCRYPTO_MIGRATION_HELPER_DELEGATE_H_
#define CRYPTOHOME_STORAGE_DIRCRYPTO_MIGRATION_HELPER_DELEGATE_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "cryptohome/data_migrator/metrics.h"
#include "cryptohome/data_migrator/migration_helper_delegate.h"
#include "cryptohome/migration_type.h"
#include "cryptohome/platform.h"

namespace cryptohome {

// Delegate class for MigrationHelper that implements logic specific to the Ext4
// migration.
class DircryptoMigrationHelperDelegate
    : public data_migrator::MigrationHelperDelegate {
 public:
  DircryptoMigrationHelperDelegate(Platform* platform,
                                   const base::FilePath& to_dir,
                                   MigrationType migration_type);
  ~DircryptoMigrationHelperDelegate() override = default;

  DircryptoMigrationHelperDelegate(const DircryptoMigrationHelperDelegate&) =
      delete;
  DircryptoMigrationHelperDelegate& operator=(
      const DircryptoMigrationHelperDelegate&) = delete;

  // data_migrator::MigrationHelperDelegate overrides:
  bool ShouldReportProgress() override;
  bool ShouldMigrateFile(const base::FilePath& child) override;
  bool ShouldCopyQuotaProjectId() override;
  bool ShouldSkipFileOnIOErrors() override;
  std::string GetMtimeXattrName() override;
  std::string GetAtimeXattrName() override;
  void RecordSkippedFile(const base::FilePath& path) override;
  int64_t FreeSpaceForMigrator() override;
  void ReportStartTime() override;
  void ReportEndTime() override;
  void ReportStartStatus(data_migrator::MigrationStartStatus status) override;
  void ReportEndStatus(data_migrator::MigrationEndStatus status) override;
  void ReportTotalSize(int total_byte_count_mb, int total_file_count) override;
  void ReportFailure(base::File::Error error_code,
                     data_migrator::MigrationFailedOperationType type,
                     const base::FilePath& path,
                     data_migrator::FailureLocationType location_type) override;
  void ReportFailedNoSpace(int initial_migration_free_space_mb,
                           int failure_free_space_mb) override;
  void ReportFailedNoSpaceXattrSizeInBytes(int total_xattr_size_bytes) override;

 private:
  Platform* const platform_;

  const base::FilePath to_dir_;

  // Name of the file to store the names of the files that are skipped during
  // the migration due to file IO error on open.
  const base::FilePath skipped_file_list_path_;

  const MigrationType migration_type_;

  // Allowlisted paths for minimal migration. May contain directories and files.
  std::vector<base::FilePath> minimal_migration_paths_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_DIRCRYPTO_MIGRATION_HELPER_DELEGATE_H_
