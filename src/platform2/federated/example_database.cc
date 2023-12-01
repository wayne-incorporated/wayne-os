// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/example_database.h"

#include <cinttypes>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <bits/stdint-intn.h>
#include <sqlite3.h>

#include "federated/utils.h"

namespace federated {

namespace {

constexpr char kMetaTableName[] = "metatable";

// Populates SQL where clause with given start and end time if they are not zero
// values, returns an empty string (i.e. no-op) otherwise.
std::string MaybeWhereClause(const base::Time& start_time,
                             const base::Time& end_time) {
  if (start_time == base::Time() && end_time == base::Time())
    return std::string();

  DCHECK(start_time < end_time)
      << "Invalid time range: start_time must < end_time";
  DCHECK(start_time >= base::Time::UnixEpoch())
      << "Invalid time range: start_time must >= UnixEpoch()";
  return base::StringPrintf("WHERE timestamp>%" PRId64
                            " AND timestamp<=%" PRId64,
                            start_time.ToJavaTime(), end_time.ToJavaTime());
}

// Used in ExampleCount to return number of examples.
int ExampleCountCallback(void* const /* int* const */ data,
                         const int col_count,
                         char** const cols,
                         char** const /* names */) {
  DCHECK(data != nullptr);
  DCHECK(cols != nullptr);

  int example_count = 0;
  if (col_count != 1 || cols[0] == nullptr ||
      !base::StringToInt(cols[0], &example_count)) {
    LOG(ERROR) << "Invalid example count results";
    return SQLITE_ERROR;
  }

  auto* const output = static_cast<int*>(data);
  *output = example_count;
  return SQLITE_OK;
}

// Used in CheckIntegrity to extract state code and result string from SQL
// exec.
int IntegrityCheckCallback(void* const /* std::string* const */ data,
                           int const col_count,
                           char** const cols,
                           char** const /* names */) {
  DCHECK(data != nullptr);
  DCHECK(cols != nullptr);

  if (col_count != 1 || cols[0] == nullptr) {
    LOG(ERROR) << "Invalid integrity check results";
    return SQLITE_ERROR;
  }

  auto* const integrity_result = static_cast<std::string*>(data);
  integrity_result->assign(cols[0]);
  return SQLITE_OK;
}

// Used in TableExists to extract state code and table_count from SQL
// exec.
int TableExistsCallback(void* const /* int* const */ data,
                        const int col_count,
                        char** const cols,
                        char** const /* names */) {
  DCHECK(data != nullptr);
  DCHECK(cols != nullptr);

  auto* const table_count = static_cast<int*>(data);
  if (col_count != 1 || cols[0] == nullptr ||
      !base::StringToInt(cols[0], table_count)) {
    LOG(ERROR) << "Table existence check failed";
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

int GetAllTableNamesCallback(
    void* const /* std::vector<std::string>* const */ data,
    const int col_count,
    char** const cols,
    char** const /* names */) {
  DCHECK(data != nullptr);
  DCHECK(cols != nullptr);

  auto* const all_table_names = static_cast<std::vector<std::string>*>(data);
  if (col_count != 1) {
    LOG(ERROR) << "GetAllTableNames failed";
    return SQLITE_ERROR;
  }
  for (size_t i = 0; i < sizeof(cols) / sizeof(char*); i++) {
    if (cols[i] == nullptr) {
      LOG(ERROR) << "GetAllTableNames gets unexpected nullptr at index " << i;
      return SQLITE_ERROR;
    }
    all_table_names->push_back(std::string(cols[i]));
  }

  return SQLITE_OK;
}

}  // namespace

ExampleDatabase::Iterator::Iterator() : stmt_(nullptr) {}

ExampleDatabase::Iterator::Iterator(sqlite3* const db,
                                    const std::string& client_name,
                                    const base::Time& start_time,
                                    const base::Time& end_time,
                                    bool descending,
                                    const size_t limit) {
  if (db == nullptr) {
    stmt_ = nullptr;
    return;
  }

  const std::string order = descending ? "DESC" : std::string();
  const std::string limit_clause =
      limit > 0 ? base::StringPrintf("LIMIT %zu", limit) : std::string();

  const std::string sql_code = base::StringPrintf(
      "SELECT id, example, timestamp FROM '%s' %s ORDER BY id %s %s;",
      client_name.c_str(), MaybeWhereClause(start_time, end_time).c_str(),
      order.c_str(), limit_clause.c_str());
  const int result =
      sqlite3_prepare_v2(db, sql_code.c_str(), -1, &stmt_, nullptr);

  if (result != SQLITE_OK) {
    LOG(ERROR) << "Couldn't compile iteration statement: "
               << sqlite3_errmsg(db);
    Close();
  }
}

ExampleDatabase::Iterator::Iterator(sqlite3* const db,
                                    const std::string& client_name)
    : ExampleDatabase::Iterator::Iterator(db,
                                          client_name,
                                          base::Time(),
                                          base::Time(),
                                          /*descending=*/false,
                                          /*limit=*/0) {}

ExampleDatabase::Iterator::Iterator(ExampleDatabase::Iterator&& o)
    : stmt_(o.stmt_) {
  o.stmt_ = nullptr;
}

ExampleDatabase::Iterator& ExampleDatabase::Iterator::operator=(
    Iterator&& other) {
  if (stmt_ != nullptr) {
    Close();
  }
  stmt_ = other.stmt_;
  other.stmt_ = nullptr;

  return *this;
}

ExampleDatabase::Iterator::~Iterator() {
  Close();
}

absl::StatusOr<ExampleRecord> ExampleDatabase::Iterator::Next() {
  if (stmt_ == nullptr) {
    return absl::InvalidArgumentError("Invalid sqlite3 statment");
  }

  // Execute retrieval step.
  const int code = sqlite3_step(stmt_);
  if (code == SQLITE_DONE) {
    Close();
    return absl::OutOfRangeError("End of iterator reached");
  }
  if (code != SQLITE_ROW) {
    Close();
    return absl::InvalidArgumentError("Couldn't retrieve next example");
  }

  // Extract step results.
  const int64_t id = sqlite3_column_int64(stmt_, 0);
  const unsigned char* const example_buffer =
      static_cast<const unsigned char*>(sqlite3_column_blob(stmt_, 1));
  const int example_buffer_len = sqlite3_column_bytes(stmt_, 1);
  const int64_t java_ts = sqlite3_column_int64(stmt_, 2);
  if (id <= 0 || example_buffer == nullptr || example_buffer_len <= 0 ||
      java_ts < 0) {
    Close();
    return absl::InvalidArgumentError("Failed to extract example");
  }

  // Populate output struct.
  ExampleRecord example_record;
  example_record.id = id;
  example_record.serialized_example =
      std::string(example_buffer, example_buffer + example_buffer_len);
  example_record.timestamp = base::Time::FromJavaTime(java_ts);
  return example_record;
}

void ExampleDatabase::Iterator::Close() {
  sqlite3_finalize(stmt_);
  stmt_ = nullptr;
}

ExampleDatabase::ExampleDatabase(const base::FilePath& db_path)
    : db_path_(db_path), db_(nullptr, nullptr) {
  // Checks that sqlite3 is compiled with threading mode = Serialized, so that
  // the db connection can be used in multiple threads. See
  // https://www.sqlite.org/threadsafe.html for more information.
  DCHECK_EQ(1, sqlite3_threadsafe());
}

ExampleDatabase::~ExampleDatabase() {
  Close();
}

bool ExampleDatabase::Init(const std::unordered_set<std::string>& clients) {
  // SQLITE_OPEN_FULLMUTEX means sqlite3 threadding mode = serialized so that
  // it's safe to access the same database connection in multiple threads.
  // This is the default when `sqlite3_threadsafe() == 1` but no harm to make a
  // double insurance with this flag.
  sqlite3* db_ptr;
  const int result = sqlite3_open_v2(
      db_path_.MaybeAsASCII().c_str(), &db_ptr,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
  db_ = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>(db_ptr,
                                                           &sqlite3_close);
  if (result != SQLITE_OK) {
    LOG(ERROR) << "Failed to connect to database: "
               << sqlite3_errmsg(db_.get());
    db_ = nullptr;
    return false;
  }

  // Prepares meta table.
  if (!TableExists(kMetaTableName) && !CreateMetaTable()) {
    LOG(ERROR) << "Failed to prepare meta table";
    Close();
    return false;
  }

  // Prepares client tables.
  for (const auto& client : clients) {
    if ((!TableExists(client) && !CreateClientTable(client))) {
      LOG(ERROR) << "Failed to prepare table for client " << client;
      Close();

      return false;
    }
  }

  return true;
}

bool ExampleDatabase::IsOpen() const {
  return db_.get() != nullptr;
}

bool ExampleDatabase::Close() {
  if (!IsOpen()) {
    return true;
  }

  // If the database is successfully closed, db_ pointer must be released.
  // Otherwise sqlite3_close will be called again on already released db_
  // pointer by the destructor, which will result in undefined behavior.
  int result = sqlite3_close(db_.get());
  if (result != SQLITE_OK) {
    // This should never happen
    LOG(ERROR) << "Failed to close database: " << sqlite3_errmsg(db_.get());
    return false;
  }

  db_.release();
  return true;
}

bool ExampleDatabase::CheckIntegrity() const {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to check integrity of a closed database";
    return false;
  }

  // Integrity_check(N) returns a single row and a single column with string
  // "ok" if there is no error. Otherwise a maximum of N rows are returned
  // with each row representing a single error.
  std::string integrity_result;
  ExecResult result = ExecSql("PRAGMA integrity_check(1)",
                              IntegrityCheckCallback, &integrity_result);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to check integrity: " << result.error_msg;
    return false;
  }

  return integrity_result == "ok";
}

bool ExampleDatabase::DeleteOutdatedExamples(
    const base::TimeDelta& example_ttl) const {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to delete examples from a closed database";
    return false;
  }

  std::vector<std::string> all_table_names;
  const ExecResult result =
      ExecSql("SELECT name FROM sqlite_master WHERE type = 'table';",
              GetAllTableNamesCallback, &all_table_names);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to get all table names: " << result.error_msg;
    return false;
  }

  base::Time expired_timestamp = base::Time::Now() - example_ttl;
  int error_count = 0;
  for (const auto& table_name : all_table_names) {
    // "sqlite_*" are sqlite reserved table names.
    if (table_name.find("sqlite_") == 0)
      continue;

    const ExecResult result = ExecSql(
        base::StringPrintf("DELETE FROM '%s' WHERE timestamp < %" PRId64 ";",
                           table_name.c_str(), expired_timestamp.ToJavaTime()));
    if (result.code != SQLITE_OK) {
      error_count++;
      LOG(ERROR) << "Failed to delete expired examples from table "
                 << table_name << "with message: " << result.error_msg;
    } else {
      DVLOG(1) << "Delete expired examples from table " << table_name
               << " count = " << sqlite3_changes(db_.get());
    }
  }
  return error_count == 0;
}

std::optional<MetaRecord> ExampleDatabase::GetMetaRecord(
    const std::string& identifier) const {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to get last used example id in a closed database";
    return std::nullopt;
  }

  // Uses prepared stmt instead of a simple ExecSql because stmt returns
  // SQLITE_DONE explicitly when there are no matching records, while ExecSql
  // just returns SQLITE_OK anyway.
  sqlite3_stmt* stmt = nullptr;
  const std::string sql = base::StringPrintf(
      "SELECT last_used_example_id, last_used_example_timestamp, timestamp "
      "FROM '%s' WHERE identifier = '%s';",
      kMetaTableName, identifier.c_str());
  int sqlite_code =
      sqlite3_prepare_v2(db_.get(), sql.c_str(), -1, &stmt, nullptr);

  if (sqlite_code != SQLITE_OK) {
    LOG(ERROR) << "Couldn't compile SELECT statement: "
               << sqlite3_errmsg(db_.get());
    return std::nullopt;
  }

  std::optional<MetaRecord> result;
  sqlite_code = sqlite3_step(stmt);
  if (sqlite_code == SQLITE_ROW) {
    MetaRecord record;
    record.last_used_example_id = sqlite3_column_int64(stmt, 0);
    record.last_used_example_timestamp =
        base::Time::FromJavaTime(sqlite3_column_int64(stmt, 1));
    record.timestamp = base::Time::FromJavaTime(sqlite3_column_int64(stmt, 2));
    result = std::move(record);
  } else if (sqlite_code == SQLITE_DONE) {
    DVLOG(1) << "Metatable doesn't have record for identifier = " << identifier;
  } else {  // This is unexpected, logs an error.
    LOG(ERROR) << "Failed to retrieve last_used_example_id for identifier = "
               << identifier;
  }

  sqlite3_finalize(stmt);

  return result;
}

bool ExampleDatabase::UpdateMetaRecord(
    const std::string& identifier, const MetaRecord& new_meta_record) const {
  DCHECK_GE(new_meta_record.last_used_example_id, 0);
  DCHECK_GE(new_meta_record.last_used_example_timestamp,
            base::Time::UnixEpoch());
  DCHECK_GE(new_meta_record.timestamp, base::Time::UnixEpoch());

  const std::string sql = base::StringPrintf(
      "INSERT INTO '%s' (identifier, last_used_example_id, "
      "last_used_example_timestamp, timestamp) VALUES("
      "'%s', %" PRId64 ", %" PRId64 ", %" PRId64
      ") ON CONFLICT(identifier) DO UPDATE SET "
      "last_used_example_id=excluded.last_used_example_id, "
      "last_used_example_timestamp=excluded.last_used_example_timestamp, "
      "timestamp=excluded.timestamp;",
      kMetaTableName, identifier.c_str(), new_meta_record.last_used_example_id,
      new_meta_record.last_used_example_timestamp.ToJavaTime(),
      new_meta_record.timestamp.ToJavaTime());

  ExecResult result = ExecSql(sql);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to update last_used_example_id for identifier: "
               << identifier << " with error message:" << result.error_msg;
    return false;
  }

  return true;
}

ExampleDatabase::Iterator ExampleDatabase::GetIterator(
    const std::string& client_name,
    const base::Time& start_time,
    const base::Time& end_time,
    bool descending,
    const size_t limit) const {
  return Iterator(db_.get(), client_name, start_time, end_time, descending,
                  limit);
}

ExampleDatabase::Iterator ExampleDatabase::GetIteratorForTesting(
    const std::string& client_name) const {
  return Iterator(db_.get(), client_name);
}

bool ExampleDatabase::InsertExample(const std::string& client_name,
                                    const ExampleRecord& example_record) {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to insert example into a closed database";
    return false;
  }

  // Compile the insertion statement.
  sqlite3_stmt* stmt = nullptr;
  const std::string sql_code =
      base::StringPrintf("INSERT INTO '%s' (example, timestamp) VALUES (?, ?);",
                         client_name.c_str());
  const int result =
      sqlite3_prepare_v2(db_.get(), sql_code.c_str(), -1, &stmt, nullptr);
  if (result != SQLITE_OK) {
    LOG(ERROR) << "Couldn't compile insertion statement: "
               << sqlite3_errmsg(db_.get());
    return false;
  }

  // Run the insertion statement.
  const bool ok =
      sqlite3_bind_blob(stmt, 1, example_record.serialized_example.c_str(),
                        example_record.serialized_example.length(),
                        nullptr) == SQLITE_OK &&
      sqlite3_bind_int64(stmt, 2, example_record.timestamp.ToJavaTime()) ==
          SQLITE_OK &&
      sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);

  if (!ok) {
    LOG(ERROR) << "Failed to insert example: " << sqlite3_errmsg(db_.get());
  }
  DVLOG(1) << "Insert example for client " << client_name;
  return ok;
}

void ExampleDatabase::DeleteAllExamples(const std::string& client_name) {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to delete from a closed database";
    return;
  }

  const ExecResult result =
      ExecSql(base::StringPrintf("DELETE FROM '%s';", client_name.c_str()));
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to delete examples: " << result.error_msg;
  }
}

bool ExampleDatabase::TableExists(const std::string& table_name) const {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to query table of a closed database";
    return false;
  }

  int table_count = 0;
  const std::string sql_code = base::StringPrintf(
      "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = "
      "'%s';",
      table_name.c_str());
  ExecResult result = ExecSql(sql_code, TableExistsCallback, &table_count);

  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to query table existence: " << result.error_msg;
    return false;
  }

  if (table_count <= 0)
    return false;

  DCHECK(table_count == 1) << "There should be only one table with name '"
                           << table_name << "'";

  return true;
}

bool ExampleDatabase::CreateClientTable(const std::string& client_name) {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to create table in a closed database";
    return false;
  }

  const std::string sql = base::StringPrintf(R"(
      CREATE TABLE '%s' (
        id         INTEGER PRIMARY KEY AUTOINCREMENT
                           NOT NULL,
        example    BLOB    NOT NULL,
        timestamp  INTEGER NOT NULL
      ))",
                                             client_name.c_str());
  const ExecResult result = ExecSql(sql);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to create table: " << result.error_msg;
    return false;
  }
  return true;
}

bool ExampleDatabase::MetaTableExists() const {
  return TableExists(std::string(kMetaTableName));
}

bool ExampleDatabase::CreateMetaTable() {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to create table in a closed database";
    return false;
  }

  const std::string sql = base::StringPrintf(
      "CREATE TABLE '%s' ("
      " identifier                    TEXT PRIMARY KEY NOT NULL,"
      " last_used_example_id          INTEGER NOT NULL,"
      " last_used_example_timestamp   INTEGER NOT NULL,"
      " timestamp                     INTEGER NOT NULL"
      ")",
      kMetaTableName);
  const ExecResult result = ExecSql(sql);
  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to create table: " << result.error_msg;
    return false;
  }
  return true;
}

int ExampleDatabase::ExampleCount(const std::string& client_name,
                                  const base::Time& start_time,
                                  const base::Time& end_time) const {
  DCHECK(start_time != base::Time() && end_time != base::Time())
      << "start_time and end_time cannot be zero values";
  return ExampleCountInternal(client_name,
                              MaybeWhereClause(start_time, end_time));
}

int ExampleDatabase::ExampleCountForTesting(
    const std::string& client_name) const {
  return ExampleCountInternal(client_name, /* where_clause = */
                              std::string());
}

int ExampleDatabase::ExampleCountInternal(
    const std::string& client_name, const std::string& where_clause) const {
  if (!IsOpen()) {
    LOG(ERROR) << "Trying to count examples in a closed database";
    return 0;
  }

  int count = 0;
  const ExecResult result =
      ExecSql(base::StringPrintf("SELECT COUNT(*) FROM '%s' %s;",
                                 client_name.c_str(), where_clause.c_str()),
              ExampleCountCallback, &count);

  if (result.code != SQLITE_OK) {
    LOG(ERROR) << "Failed to count examples: " << result.error_msg;
    return 0;
  }
  return count;
}

ExampleDatabase::ExecResult ExampleDatabase::ExecSql(
    const std::string& sql) const {
  return ExecSql(sql, nullptr, nullptr);
}

ExampleDatabase::ExecResult ExampleDatabase::ExecSql(const std::string& sql,
                                                     SqliteCallback callback,
                                                     void* const data) const {
  char* error_msg = nullptr;
  const int result =
      sqlite3_exec(db_.get(), sql.c_str(), callback, data, &error_msg);
  // According to sqlite3_exec() documentation, error_msg points to memory
  // allocated by sqlite3_malloc(), which must be freed by sqlite3_free().
  std::string error_msg_str;
  if (error_msg) {
    error_msg_str.assign(error_msg);
    sqlite3_free(error_msg);
  }
  return {result, error_msg_str};
}

}  // namespace federated
