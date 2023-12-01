// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Migration from /var/cache/reporting to /var/spool/reporting.
// Design doc: go/missive-move

#ifndef MISSIVE_MISSIVE_MIGRATION_H_
#define MISSIVE_MISSIVE_MIGRATION_H_

#include <tuple>

#include <base/files/file_path.h>

#include "missive/util/status.h"

namespace reporting {
// Migrates from the old reporting directory to the new one. Returns the
// directory (either src or dest) that is suitable for use and the status of the
// migration.
//
// In production code, this should be called as
//   Migration(base::FilePath("/var/cache/reporting"),
//   base::FilePath("/var/spool/reporting"))
std::tuple<base::FilePath, Status> Migrate(const base::FilePath& src,
                                           const base::FilePath& dest);

// Migration status for UMA stats reporting.
enum class MigrationStatusForUma {
  // Migration not needed.
  NotNeeded = 0,
  // Migration succeeded.
  Success,
  // Failed to delete files in the source dir other than the delete tag file.
  FailToDeleteSourceFiles,
  // Failed to delete deletion tag file.
  FailToDeleteDeletionTagFile,
  // Failed to create deletion tag file.
  FailToCreateDeletionTagFile,
  // Failed to delete files in the destination dir.
  FailToDeleteDestinationFiles,
  // Failed to copy files from the source to the destination dir.
  FailToCopy,
  // Destination directory does not exist.
  DestinationNotExist,
  // Max value
  kMaxValue
};

static constexpr char kMigrationStatusUmaName[] =
    "Platform.Missive.MigrationStatus";
}  // namespace reporting

#endif  // MISSIVE_MISSIVE_MIGRATION_H_
