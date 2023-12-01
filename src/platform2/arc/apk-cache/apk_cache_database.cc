// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_database.h"

#include <cinttypes>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <sqlite3.h>

namespace apk_cache {

namespace {

int IntegrityCheckCallback(void* data, int count, char** row, char** names) {
  auto* integrity_result = static_cast<std::string*>(data);
  if (!row[0]) {
    LOG(ERROR) << "Integrity check returned null";
    return SQLITE_ERROR;
  }
  integrity_result->assign(row[0]);
  return SQLITE_OK;
}

int GetSessionsCallback(void* data, int count, char** row, char** names) {
  auto* sessions_out = static_cast<std::vector<Session>*>(data);
  Session session;

  if (!row[0]) {
    LOG(ERROR) << "Session.id is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt64(row[0], &session.id)) {
    LOG(ERROR) << "Session.id is not a number";
    return SQLITE_ERROR;
  }

  if (!row[1]) {
    LOG(ERROR) << "Session.source is null";
    return SQLITE_ERROR;
  }
  session.source = row[1];

  if (!row[2]) {
    LOG(ERROR) << "Session.timestamp is null";
    return SQLITE_ERROR;
  }
  int64_t timestamp;
  if (!base::StringToInt64(row[2], &timestamp)) {
    LOG(ERROR) << "Session.timestamp is not a number";
    return SQLITE_ERROR;
  }
  session.timestamp = base::Time::FromJavaTime(timestamp);

  if (!row[3]) {
    LOG(ERROR) << "Session.status is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt(row[3], &session.status)) {
    LOG(ERROR) << "Session.status is not a number";
    return SQLITE_ERROR;
  }

  sessions_out->push_back(std::move(session));
  return SQLITE_OK;
}

int GetFileEntriesCallback(void* data, int count, char** row, char** names) {
  auto* file_entries_out = static_cast<std::vector<FileEntry>*>(data);
  FileEntry file_entry;

  if (!row[0]) {
    LOG(ERROR) << "FileEntry.id is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt64(row[0], &file_entry.id)) {
    LOG(ERROR) << "FileEntry.id is not a number";
    return SQLITE_ERROR;
  }

  if (!row[1]) {
    LOG(ERROR) << "FileEntry.package_name is null";
    return SQLITE_ERROR;
  }
  file_entry.package_name = row[1];

  if (!row[2]) {
    LOG(ERROR) << "FileEntry.version_code is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt64(row[2], &file_entry.version_code)) {
    LOG(ERROR) << "FileEntry.version_code is not a number";
    return SQLITE_ERROR;
  }

  if (!row[3]) {
    LOG(ERROR) << "FileEntry.type is null";
    return SQLITE_ERROR;
  }
  file_entry.type = row[3];

  if (row[4])
    file_entry.attributes = std::string(row[4]);

  if (!row[5]) {
    LOG(ERROR) << "FileEntry.size is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt64(row[5], &file_entry.size)) {
    LOG(ERROR) << "FileEntry.size is not a number";
    return SQLITE_ERROR;
  }

  if (row[6])
    file_entry.hash = std::string(row[6]);

  if (!row[7]) {
    LOG(ERROR) << "FileEntry.access_time is null";
    return SQLITE_ERROR;
  }
  int64_t access_time;
  if (!base::StringToInt64(row[7], &access_time)) {
    LOG(ERROR) << "FileEntry.access_time is not a number";
    return SQLITE_ERROR;
  }
  file_entry.access_time = base::Time::FromJavaTime(access_time);

  if (!row[8]) {
    LOG(ERROR) << "FileEntry.priority is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt(row[8], &file_entry.priority)) {
    LOG(ERROR) << "FileEntry.priority is not a number";
    return SQLITE_ERROR;
  }

  if (!row[9]) {
    LOG(ERROR) << "FileEntry.session_id is null";
    return SQLITE_ERROR;
  }
  if (!base::StringToInt64(row[9], &file_entry.session_id)) {
    LOG(ERROR) << "FileEntry.session_id is not a number";
    return SQLITE_ERROR;
  }

  file_entries_out->push_back(std::move(file_entry));
  return SQLITE_OK;
}

}  // namespace

std::string EscapeSQLString(const std::string& string_to_escape) {
  std::string escaped_string = string_to_escape;
  base::ReplaceSubstringsAfterOffset(&escaped_string, 0, "'", "''");
  return escaped_string;
}

ApkCacheDatabase::ApkCacheDatabase(const base::FilePath& db_path)
    : db_path_(db_path), db_(nullptr, nullptr) {}

ApkCacheDatabase::~ApkCacheDatabase() {
  Close();
}

int ApkCacheDatabase::Init() {
  sqlite3* db_ptr;
  int result = sqlite3_open(db_path_.MaybeAsASCII().c_str(), &db_ptr);
  db_ = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>(db_ptr,
                                                           &sqlite3_close);
  if (result == SQLITE_OK) {
    result = EnableForeignKey();
  } else {
    LOG(ERROR) << "Failed to connect to database: " << result;
    db_ = nullptr;
  }
  return result;
}

bool ApkCacheDatabase::IsOpen() {
  return db_.get() != nullptr;
}

int ApkCacheDatabase::Close() {
  if (!db_)
    return SQLITE_OK;

  // Error code will be returned in case of error. The caller may retry in this
  // case. If the database is successfully closed, db_ pointer must be released,
  // Otherwise sqlite3_close will be called again on already released db_
  // pointer by the destructor, which will result in undefined behavior.
  int result = sqlite3_close(db_.get());
  if (result == SQLITE_OK)
    db_.release();

  return result;
}

bool ApkCacheDatabase::CheckIntegrity() const {
  // Integrity_check(N) returns a single row and a single column with string
  // "ok" if there is no error. Otherwise a maximum of N rows are returned with
  // each row representing a single error.
  std::string integrity_result;
  ExecResult result = ExecSQL("PRAGMA integrity_check(1)",
                              IntegrityCheckCallback, &integrity_result);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to check integrity: (" << result.code << ") "
               << result.error_msg;
    return false;
  }

  return integrity_result == "ok";
}

bool ApkCacheDatabase::SessionsTableExists() const {
  ExecResult result = ExecSQL("SELECT id FROM sessions LIMIT 1");
  return result.error_msg.find("no such table") == std::string::npos;
}

int64_t ApkCacheDatabase::InsertSession(const Session& session) const {
  const std::string sql = base::StringPrintf(
      "INSERT INTO sessions (source, timestamp, status)"
      " VALUES ('%s', %" PRId64 ", %d)",
      EscapeSQLString(session.source).c_str(), session.timestamp.ToJavaTime(),
      session.status);
  ExecResult result = ExecSQL(sql);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to insert session: (" << result.code << ") "
               << result.error_msg;
    return 0;
  }
  return sqlite3_last_insert_rowid(db_.get());
}

std::optional<std::vector<Session>> ApkCacheDatabase::GetSessions() const {
  std::vector<Session> sessions;
  ExecResult result = ExecSQL("SELECT id,source,timestamp,status FROM sessions",
                              GetSessionsCallback, &sessions);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to query: (" << result.code << ") "
               << result.error_msg;
    return std::nullopt;
  }
  return std::make_optional(std::move(sessions));
}

std::optional<std::vector<FileEntry>> ApkCacheDatabase::GetFileEntries() const {
  std::vector<FileEntry> file_entries;
  ExecResult result = ExecSQL(
      "SELECT id,package_name,version_code,type,"
      "attributes,size,hash,access_time,priority,"
      "session_id FROM file_entries",
      GetFileEntriesCallback, &file_entries);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to query: (" << result.code << ") "
               << result.error_msg;
    return std::nullopt;
  }

  return std::make_optional(std::move(file_entries));
}

bool ApkCacheDatabase::DeleteSession(int64_t session_id) const {
  const std::string sql = base::StringPrintf(
      "DELETE FROM sessions WHERE id = %" PRId64, session_id);
  if (ExecDeleteSQL(sql) != 1) {
    LOG(ERROR) << "Session " << session_id << " does not exist in the database";
    return false;
  }

  return true;
}

int ApkCacheDatabase::DeleteSessionsWithoutFileEntries(
    int64_t current_session) const {
  const std::string sql = base::StringPrintf(
      "DELETE FROM sessions WHERE id IN ("
      "SELECT s.id FROM sessions s LEFT JOIN file_entries f ON "
      "s.id = f.session_id WHERE f.id IS NULL AND s.id != %" PRId64 ")",
      current_session);
  return ExecDeleteSQL(sql);
}

bool ApkCacheDatabase::DeleteFileEntry(int64_t file_id) const {
  const std::string sql = base::StringPrintf(
      "DELETE FROM file_entries WHERE id = %" PRId64, file_id);
  if (ExecDeleteSQL(sql) != 1) {
    LOG(ERROR) << "File entry " << file_id << " does not exist in the database";
    return false;
  }

  return true;
}

int ApkCacheDatabase::DeletePackage(const std::string& name,
                                    int64_t version) const {
  const std::string sql = base::StringPrintf(
      "DELETE FROM file_entries WHERE "
      "package_name = '%s' AND version_code = %" PRId64,
      EscapeSQLString(name).c_str(), version);

  return ExecDeleteSQL(sql);
}

bool ApkCacheDatabase::UpdateSessionStatus(int64_t id, int32_t status) const {
  const std::string sql = base::StringPrintf(
      "UPDATE sessions SET status = %" PRId32 " WHERE id = %" PRId64, status,
      id);
  ExecResult result = ExecSQL(sql);

  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to update session status: (" << result.code << ") "
               << result.error_msg;
    return -1;
  }

  if (sqlite3_changes(db_.get()) != 1) {
    LOG(ERROR) << "Session " << id << " does not exist";
    return false;
  }

  return true;
}

int ApkCacheDatabase::EnableForeignKey() const {
  ExecResult result = ExecSQL("PRAGMA foreign_keys = ON");
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to enable foreign key: (" << result.code << ") "
               << result.error_msg;
  }

  return result.code;
}

ApkCacheDatabase::ExecResult ApkCacheDatabase::ExecSQL(
    const std::string& sql) const {
  return ExecSQL(sql, nullptr, nullptr);
}

ApkCacheDatabase::ExecResult ApkCacheDatabase::ExecSQL(const std::string& sql,
                                                       SqliteCallback callback,
                                                       void* data) const {
  char* error_msg = nullptr;
  int result = sqlite3_exec(db_.get(), sql.c_str(), callback, data, &error_msg);
  // According to sqlite3_exec() documentation, error_msg points to memory
  // allocated by sqlite3_malloc(), which must be freed by sqlite3_free().
  std::string error_msg_str;
  if (error_msg) {
    error_msg_str.assign(error_msg);
    sqlite3_free(error_msg);
  }
  return {result, error_msg_str};
}

int ApkCacheDatabase::ExecDeleteSQL(const std::string& sql) const {
  ExecResult result = ExecSQL(sql);

  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to delete: (" << result.code << ") "
               << result.error_msg;
    return -1;
  }

  return sqlite3_changes(db_.get());
}

}  // namespace apk_cache
