// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_ctl_commands.h"

#include <sysexits.h>

#include <iostream>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <sqlite3.h>

#include "arc/apk-cache/apk_cache_database.h"
#include "arc/apk-cache/apk_cache_utils.h"

namespace apk_cache {

ExitCode CommandLs(const base::FilePath& cache_root, std::ostream& out_stream) {
  base::FilePath db_path = cache_root.AppendASCII(kDatabaseFile);
  base::FilePath files_base = cache_root.AppendASCII(kFilesBase);

  // If database file does not exist, exit.
  if (!base::PathExists(db_path)) {
    LOG(ERROR) << "APK Cache database does not exist.";
    return ExitCode::kErrorNoDatabase;
  }

  // Open database connection
  apk_cache::ApkCacheDatabase apk_cache_database(db_path);
  if (apk_cache_database.Init() != SQLITE_OK) {
    LOG(ERROR) << "Failed to open database.";
    return ExitCode::kErrorDatabaseOpenFail;
  }

  auto file_entries = apk_cache_database.GetFileEntries();
  if (!file_entries) {
    LOG(ERROR) << "Failed to query in database.";
    return ExitCode::kErrorDatabaseQueryFail;
  }

  for (const FileEntry& entry : *file_entries) {
    out_stream << "ID: " << entry.id << "\tPackage: " << entry.package_name
               << "\tVersion: " << entry.version_code
               << "\tPriority: " << entry.priority << "\tType: " << entry.type
               << "\tTimestamp: " << entry.access_time
               << "\tHash: " << entry.hash.value_or("null")
               << "\tSize: " << entry.size << "\tSize on disk: ";

    // Check actual file size on disk.
    base::FilePath file_path =
        files_base.AppendASCII(GetFileNameById(entry.id));

    int64_t file_size;
    if (base::GetFileSize(file_path, &file_size))
      out_stream << file_size;
    else
      out_stream << "null";

    out_stream << std::endl;
  }

  return ExitCode::kOk;
}

}  // namespace apk_cache
