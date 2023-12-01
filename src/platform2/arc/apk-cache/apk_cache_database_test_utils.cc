// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_database_test_utils.h"

#include <array>
#include <cinttypes>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <sqlite3.h>

#include "arc/apk-cache/apk_cache_database.h"

namespace apk_cache {

namespace {

constexpr std::array<const char*, 8> kCreateDatabaseSQL = {
    "PRAGMA foreign_keys = off",
    "CREATE TABLE sessions ("
    "  id         INTEGER PRIMARY KEY AUTOINCREMENT"
    "                     NOT NULL,"
    "  source     TEXT    NOT NULL,"
    "  timestamp  INTEGER NOT NULL,"
    "  attributes TEXT,"
    "  status     INTEGER NOT NULL"
    ")",
    "CREATE TABLE file_entries ("
    "  id           INTEGER PRIMARY KEY AUTOINCREMENT"
    "                       NOT NULL,"
    "  package_name TEXT    NOT NULL,"
    "  version_code INTEGER NOT NULL,"
    "  type         TEXT    NOT NULL,"
    "  attributes   TEXT,"
    "  size         INTEGER NOT NULL,"
    "  hash         TEXT,"
    "  access_time  INTEGER NOT NULL,"
    "  priority     INTEGER NOT NULL,"
    "  session_id   INTEGER NOT NULL,"
    "  FOREIGN KEY ("
    "      session_id"
    "  )"
    "  REFERENCES sessions (id) ON UPDATE NO ACTION"
    "                           ON DELETE CASCADE"
    ")",
    "CREATE INDEX index_hash ON file_entries ("
    "  hash"
    ")",
    "CREATE INDEX index_package_version_type ON file_entries ("
    "  package_name,"
    "  version_code,"
    "  type"
    ")",
    "CREATE INDEX index_session_id ON file_entries ("
    "  session_id"
    ")",
    "CREATE INDEX index_status ON sessions ("
    "  status"
    ")",
    "PRAGMA foreign_keys = on"};

int ExecSQL(const base::FilePath& db_path,
            const std::vector<std::string>& sqls) {
  sqlite3* db;
  int result;
  result = sqlite3_open(db_path.MaybeAsASCII().c_str(), &db);
  std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db_ptr(db, &sqlite3_close);
  if (result != SQLITE_OK)
    return result;

  for (const auto& sql : sqls) {
    result = sqlite3_exec(db_ptr.get(), sql.c_str(), nullptr, nullptr, nullptr);
    if (result != SQLITE_OK)
      return result;
  }

  return sqlite3_close(db_ptr.release());
}

}  // namespace

int CreateDatabaseForTesting(const base::FilePath& db_path) {
  std::vector<std::string> create_db_sql(kCreateDatabaseSQL.begin(),
                                         kCreateDatabaseSQL.end());
  return ExecSQL(db_path, create_db_sql);
}

bool InsertSessionForTesting(const base::FilePath& db_path,
                             const Session& session) {
  const std::string sql = base::StringPrintf(
      "INSERT INTO sessions (id,source,timestamp,status) VALUES "
      "(%" PRId64 ", '%s', %" PRId64 ", %" PRId32 ")",
      session.id, EscapeSQLString(session.source).c_str(),
      session.timestamp.ToJavaTime(), session.status);
  return ExecSQL(db_path, {sql}) == SQLITE_OK;
}

bool InsertFileEntryForTesting(const base::FilePath& db_path,
                               const FileEntry& file_entry) {
  std::string attributes_in_sql;
  if (file_entry.attributes) {
    attributes_in_sql = base::StringPrintf(
        "'%s'", EscapeSQLString(*(file_entry.attributes)).c_str());
  } else {
    attributes_in_sql = "null";
  }

  std::string hash_in_sql;
  if (file_entry.hash) {
    hash_in_sql =
        base::StringPrintf("'%s'", EscapeSQLString(*(file_entry.hash)).c_str());
  } else {
    hash_in_sql = "null";
  }

  std::string sql = base::StringPrintf(
      "INSERT INTO file_entries (id,package_name,version_code,type,"
      "attributes,size,hash,access_time,priority,session_id) VALUES"
      "(%" PRId64 ", '%s', %" PRId64 ", '%s', %s, %" PRId64 ", %s, %" PRId64
      ", %" PRId32 ", %" PRId64 ")",
      file_entry.id, EscapeSQLString(file_entry.package_name).c_str(),
      file_entry.version_code, EscapeSQLString(file_entry.type).c_str(),
      attributes_in_sql.c_str(), file_entry.size, hash_in_sql.c_str(),
      file_entry.access_time.ToJavaTime(), file_entry.priority,
      file_entry.session_id);
  return ExecSQL(db_path, {sql}) == SQLITE_OK;
}

bool UpdateSessionTimestampForTesting(const base::FilePath& db_path,
                                      int64_t id,
                                      const base::Time& timestamp) {
  const std::string sql = base::StringPrintf(
      "UPDATE sessions SET timestamp = %" PRId64 " WHERE id = %" PRId64,
      timestamp.ToJavaTime(), id);
  return ExecSQL(db_path, {sql}) == SQLITE_OK;
}

bool UpdateSessionStatusForTesting(const base::FilePath& db_path,
                                   int64_t id,
                                   int32_t status) {
  const std::string sql = base::StringPrintf(
      "UPDATE sessions SET status = %" PRId32 " WHERE id = %" PRId64, status,
      id);
  return ExecSQL(db_path, {sql}) == SQLITE_OK;
}

bool UpdateFileAccessTimeForTesting(const base::FilePath& db_path,
                                    int64_t id,
                                    const base::Time& access_time) {
  const std::string sql = base::StringPrintf(
      "UPDATE file_entries SET access_time = %" PRId64 " WHERE id = %" PRId64,
      access_time.ToJavaTime(), id);
  return ExecSQL(db_path, {sql}) == SQLITE_OK;
}

bool DeleteFilesOfTypeForTesting(const base::FilePath& db_path,
                                 const std::string& package_name,
                                 int64_t version_code,
                                 const std::string& type) {
  const std::string sql = base::StringPrintf(
      "DELETE FROM file_entries WHERE package_name = '%s'"
      " AND version_code = %" PRId64 " AND type = '%s'",
      EscapeSQLString(package_name).c_str(), version_code,
      EscapeSQLString(type).c_str());
  return ExecSQL(db_path, {sql}) == SQLITE_OK;
}

}  // namespace apk_cache
