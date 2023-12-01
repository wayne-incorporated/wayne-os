// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/cache_cleaner_db.h"

#include <stdint.h>

#include <array>
#include <cinttypes>
#include <iomanip>
#include <set>
#include <tuple>
#include <unordered_set>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/files/file_util.h>
#include <sqlite3.h>

#include "arc/apk-cache/apk_cache_database.h"
#include "arc/apk-cache/apk_cache_utils.h"
#include "arc/apk-cache/cache_cleaner_utils.h"

namespace apk_cache {

// Cache cleaner session source.
constexpr char kCacheCleanerSessionSource[] = "cache_cleaner";

// Maximum age of sessions.
constexpr base::TimeDelta kSessionMaxAge = base::Minutes(10);

// Maximum age of cached files. If a file expires, the whole package will be
// removed.
constexpr base::TimeDelta kValidityPeriod = base::Days(30);

namespace {

// A package is represented by name and version. All file entries with the same
// package name and version code belongs to the same package.
struct Package {
  const std::string name;
  const int64_t version;
  Package(const std::string& name, int64_t version)
      : name(name), version(version) {}
};

inline bool operator<(const Package& lhs, const Package& rhs) {
  return std::tie(lhs.name, lhs.version) < std::tie(rhs.name, rhs.version);
}

}  // namespace

OpaqueFilesCleaner::OpaqueFilesCleaner(const base::FilePath& cache_root)
    : cache_root_(cache_root),
      db_path_(cache_root.Append(kDatabaseFile)),
      files_path_(cache_root.Append(kFilesBase)) {}

OpaqueFilesCleaner::~OpaqueFilesCleaner() = default;

bool OpaqueFilesCleaner::Clean() {
  if (!base::DirectoryExists(cache_root_)) {
    LOG(ERROR) << "APK cache directory " << cache_root_.value()
               << " does not exist";
    return false;
  }

  // Delete files directory if database file does not exist.
  if (!base::PathExists(db_path_)) {
    LOG(INFO) << "Database file does not exist";
    return DeleteFiles();
  }

  ApkCacheDatabase db(db_path_);

  if (db.Init() != SQLITE_OK) {
    LOG(ERROR) << "Cannot connect to database " << db_path_.MaybeAsASCII();
    return DeleteCache();
  }

  // Delete the whole cache if database fails integrity check.
  if (!db.CheckIntegrity()) {
    LOG(ERROR) << "Database integrity check failed";
    return DeleteCache();
  }

  // Delete files directory if database is an empty file, i.e. desired tables
  // do not exist.
  if (!db.SessionsTableExists()) {
    LOG(INFO) << "Database is empty";
    return DeleteFiles();
  }

  // Clean stale sessions
  if (!CleanStaleSessions(db)) {
    LOG(ERROR) << "Failed to clean stale sessions";
    DeleteCache();
    return false;
  }

  // Exit normally if any other session is active.
  if (IsOtherSessionActive(db))
    return true;

  // Open cache cleaner session.
  int64_t session_id = OpenSession(db);
  if (session_id == 0) {
    LOG(ERROR) << "Failed to create session";
    DeleteCache();
    return false;
  }

  bool success = true;

  if (!CleanOutdatedFiles(db))
    success = false;

  if (!CleanSessionsWithoutFile(db, session_id))
    success = false;

  if (!CleanFiles(db))
    success = false;

  // Close cache cleaner session.
  if (!CloseSession(db, session_id))
    success = false;

  int result = db.Close();
  if (result != SQLITE_OK) {
    LOG(ERROR) << "Failed to close database: " << result;
    return false;
  }
  return success;
}

bool OpaqueFilesCleaner::DeleteCache() const {
  if (RemoveUnexpectedItemsFromDir(
          cache_root_,
          base::FileEnumerator::FileType::FILES |
              base::FileEnumerator::FileType::DIRECTORIES |
              base::FileEnumerator::FileType::SHOW_SYM_LINKS,
          {})) {
    LOG(INFO) << "Cleared cache";
    return true;
  }

  LOG(ERROR) << "Failed to delete cache";
  return false;
}

bool OpaqueFilesCleaner::DeleteFiles() const {
  if (base::PathExists(files_path_) &&
      brillo::DeletePathRecursively(files_path_))
    return true;

  LOG(ERROR) << "Failed to delete files directory";
  return false;
}

bool OpaqueFilesCleaner::CleanStaleSessions(const ApkCacheDatabase& db) const {
  auto sessions = db.GetSessions();
  if (!sessions)
    return false;

  base::Time current_time = base::Time::Now();

  for (const Session& session : *sessions) {
    if (session.status == kSessionStatusOpen) {
      // Check if the session is expired. A session will expire if the process
      // that created it exited abnormally. For example, Play Store might be
      // killed during streaming files because of system shutdown. In this
      // situation the dead session will never be closed normally and will block
      // other sessions from being created.
      base::TimeDelta age = current_time - session.timestamp;
      if (age.InSeconds() < 0)
        LOG(WARNING) << "Session " << session.id << " is in the future";
      else if (age > kSessionMaxAge)
        LOG(WARNING) << "Session " << session.id << " expired";
      else
        continue;

      if (!db.DeleteSession(session.id))
        return false;
    }
  }

  return true;
}

bool OpaqueFilesCleaner::IsOtherSessionActive(
    const ApkCacheDatabase& db) const {
  auto sessions = db.GetSessions();
  if (!sessions)
    return true;

  for (const Session& session : *sessions) {
    if (session.status == kSessionStatusOpen) {
      LOG(INFO) << "Session " << session.id << " from " << session.source
                << " is active";
      return true;
    }
  }

  return false;
}

int64_t OpaqueFilesCleaner::OpenSession(const ApkCacheDatabase& db) const {
  Session session;
  session.source = kCacheCleanerSessionSource;
  session.timestamp = base::Time::Now();
  session.status = kSessionStatusOpen;

  return db.InsertSession(session);
}

bool OpaqueFilesCleaner::CloseSession(const ApkCacheDatabase& db,
                                      uint64_t id) const {
  return db.UpdateSessionStatus(id, kSessionStatusClosed);
}

bool OpaqueFilesCleaner::CleanOutdatedFiles(const ApkCacheDatabase& db) const {
  auto file_entries = db.GetFileEntries();
  if (!file_entries)
    return false;

  std::set<Package> packages_to_delete;

  base::Time current_time = base::Time::Now();

  for (const FileEntry& file_entry : *file_entries) {
    // Check timestamp.
    base::TimeDelta age = current_time - file_entry.access_time;
    if (age > kValidityPeriod) {
      LOG(INFO) << "Found outdated file " << file_entry.id;
      packages_to_delete.emplace(file_entry.package_name,
                                 file_entry.version_code);
    }
  }

  // Delete all invalid packages.
  for (const Package& package : packages_to_delete) {
    int deleted_rows = db.DeletePackage(package.name, package.version);
    if (deleted_rows > 0)
      LOG(INFO) << "Deleted " << deleted_rows << " files in package "
                << package.name << " version " << package.version;
  }

  return true;
}

bool OpaqueFilesCleaner::CleanSessionsWithoutFile(
    const ApkCacheDatabase& db, int64_t cleaner_session_id) const {
  int result = db.DeleteSessionsWithoutFileEntries(cleaner_session_id);
  if (result > 0)
    LOG(INFO) << "Deleted " << result << " sessions";

  return result != -1;
}

bool OpaqueFilesCleaner::CleanFiles(const ApkCacheDatabase& db) const {
  // Get all recorded file entries.
  auto file_entries = db.GetFileEntries();
  if (!file_entries)
    return false;

  // Convert ID to file name
  std::unordered_set<std::string> known_file_names;
  for (const FileEntry& file_entry : *file_entries)
    known_file_names.insert(GetFileNameById(file_entry.id));

  return RemoveUnexpectedItemsFromDir(
      files_path_,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS,
      known_file_names);
}

}  // namespace apk_cache
