// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/missive/migration.h"

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/strcat.h>

#include "missive/analytics/metrics.h"
#include "missive/util/file.h"

namespace reporting {

namespace {

using Metrics = analytics::Metrics;

constexpr char kDeletionTagFile[] = ".DELETE-MISSIVE";

// Deletes the directory we migrate from. Deletes files other than
// .DELETE-MISSIVE first, then .DELETE-MISSIVE. Returns the status.
Status DeleteSrcDir(const base::FilePath& src) {
  // Delete files other than .DELETE-MISSIVE first
  const base::FilePath deletion_tag_file_path = src.Append(kDeletionTagFile);
  if (!DeleteFilesWarnIfFailed(
          base::FileEnumerator(
              src, /*recursive=*/true,
              base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES),
          base::BindRepeating(
              [](const base::FilePath& deletion_tag_file_path,
                 const base::FilePath& path) {
                return path != deletion_tag_file_path;
              },
              deletion_tag_file_path))) {
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::FailToDeleteSourceFiles);
    return Status{error::INTERNAL,
                  base::StrCat({"Failed to delete files in ",
                                src.MaybeAsASCII(), ". Migration failed."})};
  }

  // Delete the deletion tag file.
  if (!base::DeleteFile(deletion_tag_file_path)) {
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::FailToDeleteDeletionTagFile);
    return Status{error::INTERNAL, base::StrCat({"Failed to delete ",
                                                 deletion_tag_file_path.value(),
                                                 ". Migration failed."})};
  }

  LOG(INFO) << "Successfully deleted files in " << src.MaybeAsASCII() << ".";
  return Status::StatusOK();
}
}  // namespace

std::tuple<base::FilePath, Status> Migrate(const base::FilePath& src,
                                           const base::FilePath& dest) {
  if (!base::DirectoryExists(dest)) {
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::DestinationNotExist);
    return {src, Status{error::FAILED_PRECONDITION,
                        base::StrCat({dest.MaybeAsASCII(),
                                      " does not exist. It should have been "
                                      "created in the upstart script."})}};
  }

  if (!base::DirectoryExists(src) || base::IsDirectoryEmpty(src)) {
    // The migration has been successfully done before or has never been needed.
    VLOG(1) << "Detected empty directory or not detected " << src.MaybeAsASCII()
            << ", migration not needed.";
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::NotNeeded);
    return {dest, Status::StatusOK()};
  }

  const base::FilePath deletion_tag_file_path = src.Append(kDeletionTagFile);
  if (base::PathExists(deletion_tag_file_path)) {
    // The migration has reached the final step of deleting the src directory
    // but couldn't finish it last time.
    LOG(INFO) << "Detected file " << deletion_tag_file_path.MaybeAsASCII()
              << ", start deleting files in " << src.MaybeAsASCII() << "...";
    if (Status deletion_status = DeleteSrcDir(src); !deletion_status.ok()) {
      // UMA stats already reported in DeleteSrcDir
      return {dest, deletion_status};
    }
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::Success);
    return {dest, Status::StatusOK()};
  }

  if (!base::IsDirectoryEmpty(dest)) {
    // Likely we reach here because a failed migration run occurred last time.
    // Clean it up to reduce the chance of keeping corrupted files.
    LOG(INFO) << dest << " is not empty. Cleaning it up...";
    if (!DeleteFilesWarnIfFailed(base::FileEnumerator(
            dest, /*recursive=*/true,
            base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES))) {
      Metrics::SendEnumToUMA(
          kMigrationStatusUmaName,
          MigrationStatusForUma::FailToDeleteDestinationFiles);
      return {src, Status{error::INTERNAL,
                          base::StrCat({"Failed to delete files in ",
                                        dest.MaybeAsASCII(),
                                        ". Migration failed."})}};
    }
  }

  // Now all cleanup and edge cases have been handled, here comes the main logic
  // of migration.

  // We can't move the directory because "mv -Z" also updates SELinux contexts
  // recursively. If it fails in the middle of the execution, we have no easy
  // way to know the migration has failed.
  if (!base::CopyDirectory(
          // Without .Append("."), src would be copied as a sub dir of dest
          src.Append("."), dest, /*recursive=*/true)) {
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::FailToCopy);
    return {src,
            Status{error::INTERNAL,
                   base::StrCat({"Failed to copy files from ",
                                 src.MaybeAsASCII(), " to ",
                                 dest.MaybeAsASCII(), ". Migration failed."})}};
  }

  // Create the tag file that signals it is ready to delete src.
  if (!base::WriteFile(deletion_tag_file_path, "")) {
    Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                           MigrationStatusForUma::FailToCreateDeletionTagFile);
    return {base::PathExists(deletion_tag_file_path) ? dest : src,
            Status{error::INTERNAL,
                   base::StrCat({"Failed to create ",
                                 deletion_tag_file_path.MaybeAsASCII()})}};
  }

  // Cleanup everything in src
  if (Status deletion_status = DeleteSrcDir(src); !deletion_status.ok()) {
    // UMA stats already reported in DeleteSrcDir
    return {dest, deletion_status};
  }

  Metrics::SendEnumToUMA(kMigrationStatusUmaName,
                         MigrationStatusForUma::Success);
  return {dest, Status::StatusOK()};
}
}  // namespace reporting
