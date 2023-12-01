// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_APK_CACHE_CACHE_CLEANER_DB_H_
#define ARC_APK_CACHE_CACHE_CLEANER_DB_H_

#include <array>
#include <string>

#include "arc/apk-cache/apk_cache_database.h"

namespace apk_cache {
class ApkCacheDatabase;
}  // namespace apk_cache

namespace base {
class FilePath;
class TimeDelta;
}  // namespace base

namespace apk_cache {

// Cache cleaner session source for testing.
extern const char kCacheCleanerSessionSource[];

// Maximum session age for testing.
extern const base::TimeDelta kSessionMaxAge;

extern const base::TimeDelta kValidityPeriod;

// Converts file ID to file name.
std::string GetFileNameById(int64_t id);

// Cleans opaque files organized by APK cache database. Path to the cache
// directory must be provided as |cache_root| in the constructor.
class OpaqueFilesCleaner {
 public:
  explicit OpaqueFilesCleaner(const base::FilePath& cache_root);

  // Not copyable or movable.
  OpaqueFilesCleaner(const OpaqueFilesCleaner&) = delete;
  OpaqueFilesCleaner& operator=(const OpaqueFilesCleaner&) = delete;

  ~OpaqueFilesCleaner();

  // Performs cleaning of opaque files organized by database in the APK cache
  // directory. Also deletes invalid entries in the database. Returns true if
  // all the intended files and directories were successfully deleted.
  bool Clean();

 private:
  // Deletes all files in cache in case of database corruption.
  bool DeleteCache() const;
  // Deletes all files in |files| directory.
  bool DeleteFiles() const;
  // Deletes expired sessions and sessions that have a timestamp in the future.
  // Returns true if successful.
  bool CleanStaleSessions(const ApkCacheDatabase& db) const;
  // Checks if any other session is active. Returns true if there is other
  // session active.
  bool IsOtherSessionActive(const ApkCacheDatabase& db) const;
  // Creates a new cache cleaner session with open status. Returns ID. Returns 0
  // if new session cannot be created.
  int64_t OpenSession(const ApkCacheDatabase& db) const;
  // Closes a cache cleaner session. Returns true if successful.
  bool CloseSession(const ApkCacheDatabase& db, uint64_t id) const;
  // Deletes packages with outdated files. Returns true if successful.
  bool CleanOutdatedFiles(const ApkCacheDatabase& db) const;
  // Deletes sessions without any reference from |file_entries| table. Current
  // cleaner session is specified in |cleaner_session_id|.
  bool CleanSessionsWithoutFile(const ApkCacheDatabase& db,
                                int64_t cleaner_session_id) const;
  // Cleans up files in files/ directory. Deletes all files without a record in
  // |file_entries| table.
  bool CleanFiles(const ApkCacheDatabase& db) const;

  base::FilePath cache_root_;
  base::FilePath db_path_;
  base::FilePath files_path_;
};

}  // namespace apk_cache

#endif  // ARC_APK_CACHE_CACHE_CLEANER_DB_H_
