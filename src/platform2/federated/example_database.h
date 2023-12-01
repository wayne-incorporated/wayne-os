// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_EXAMPLE_DATABASE_H_
#define FEDERATED_EXAMPLE_DATABASE_H_

#include <cstdint>

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <absl/status/statusor.h>
#include <base/files/file_path.h>
#include <base/time/time.h>
#include <sqlite3.h>

namespace federated {

// MetaRecord objects stored in the metatable. It records the last used example
// in the latest successful round of a task (identifier composed of
// population_name and task_name).
struct MetaRecord {
  std::string identifier;
  int64_t last_used_example_id;
  base::Time last_used_example_timestamp;
  base::Time timestamp;
};

// Example objects stored in corresponding `client_name` tables.
// An example represents a training example of federated computation.
struct ExampleRecord {
  // The ID of this example in the client table. Only populated in records
  // being retrieved from (c.f. being inserted into) the example database.
  int64_t id = -1;

  std::string serialized_example;
  base::Time timestamp;
};

// Provides access to example database.
//
// WARNING: Do not pass strings to these methods (e.g. Init, GetIterator) that
//          have not been carefully sanitized. This class does not perform
//          string sanitization and is therefore susceptible to SQL code
//          injection.
//
// Example usage:
// Construct and initialize:
//    ExampleDatabase db(db_path);
//    if(!db.Init(kTestClients) || !db.IsOpen() || !db.CheckIntegrity() ||
//       !db.DeleteOutdatedExamples(example_ttl)) {
//      // Error handling.
//    }
//
// Insert an example:
//    ExampleRecord example_record;
//    example_record.serialized_example = serialized_example;
//    example_record.timestamp = base::Time::Now();
//    db.InsertExample(client_name, example_record);
//
// Query examples:
//    ExampleDatabase::Iterator it =
//        db.GetIterator("client_1", start_timestamp, end_timestamp);
//    while (true) {
//      const absl::StatusOr<ExampleRecord> result = it.Next();
//      if (result.ok()) {
//        // Do something with *result.
//
//        continue;
//      }
//
//      if (absl::IsOutOfRange(result)) {
//        // End of iterator.
//      } else {
//        // Handle error.
//      }
//    }
//
// See example_database_test.cc and storage_manager_impl.cc for more details.

class ExampleDatabase {
 public:
  // Handles one read-only iteration through a table.
  struct Iterator final {
   public:
    Iterator();
    // Iterator through example within time range (start_time, end_time].
    Iterator(sqlite3* db,
             const std::string& client_name,
             const base::Time& start_time,
             const base::Time& end_time,
             bool descending,
             size_t limit);
    Iterator(sqlite3* db, const std::string& client_name);
    Iterator(const Iterator& other) = delete;
    Iterator& operator=(const Iterator& other) = delete;
    Iterator(Iterator&& other);
    Iterator& operator=(Iterator&& other);
    ~Iterator();

    // Returns the next example, an "out of range" error if the end of the
    // iteration has been reached, or any other error if example fetching
    // failed.
    absl::StatusOr<ExampleRecord> Next();

    // Releases sqlite resources / locks.
    //
    // Called automatically when the iteration is complete or the iterator is
    // destroyed, but must be called manually when iteration is abandoned
    // early. The database cannot be closed unless all iterators have been
    // closed by one means or another.
    void Close();

   private:
    sqlite3_stmt* stmt_;
  };

  // Creates an instance to talk to the database file at `db_path`. Init() must
  // be called to establish connection.
  explicit ExampleDatabase(const base::FilePath& db_path);
  ExampleDatabase(const ExampleDatabase&) = delete;
  ExampleDatabase& operator=(const ExampleDatabase&) = delete;

  virtual ~ExampleDatabase();

  // Initializes database connection. Must be called before any other queries.
  // Returns true if no error occurred.
  //
  // WARNING: client names are used to construct SQL statements but are not
  //          sanitized in any way. Therefore this method is susceptible to
  //          code injection unless the provided names are carefully vetted or
  //          sanitized.
  virtual bool Init(const std::unordered_set<std::string>& clients);
  // Returns true if the database connection is open.
  virtual bool IsOpen() const;
  // Closes database connection. Returns true if no error occurred.
  virtual bool Close();
  // Runs sqlite built-in integrity check. Returns true if no error is found.
  virtual bool CheckIntegrity() const;

  // Deletes expired examples from all client tables in the db. They all have a
  // timestamp column. Returns true if no error occurred.
  virtual bool DeleteOutdatedExamples(const base::TimeDelta& example_ttl) const;

  // Returns identifier's meta record if meta table has its record, otherwise
  // returns nullopt;
  virtual std::optional<MetaRecord> GetMetaRecord(
      const std::string& identifier) const;

  // Updates the identifier's last_used_example_id to meta table.
  virtual bool UpdateMetaRecord(const std::string& identifier,
                                const MetaRecord& new_meta_record) const;

  // Returns an iterator through the examples for the given client within the
  // time range. Limits examples if `limit` > 0, otherwise iterates through all
  // examples in the range.
  //
  // WARNING: client names are used to construct SQL statements but are not
  //          sanitized in any way. Therefore this method is susceptible to
  //          code injection unless the provided names are carefully vetted
  //          or sanitized.
  virtual Iterator GetIterator(const std::string& client_name,
                               const base::Time& start_time,
                               const base::Time& end_time,
                               bool descending = false,
                               size_t limit = 0) const;

  // Similar to GetIterator but without time range, returns an iterator through
  // all examples for the given client.
  virtual Iterator GetIteratorForTesting(const std::string& client_name) const;

  // Inserts example into the table matching its client_name. Returns true
  // if no error occurred.
  //
  // WARNING: client names are used to construct SQL statements but are not
  //          sanitized in any way. Therefore this method is susceptible to
  //          code injection unless the provided names are carefully vetted or
  //          sanitized.
  virtual bool InsertExample(const std::string& client_name,
                             const ExampleRecord& example_record);

  // Returns the count of examples in the client's table within the time range.
  //
  // WARNING: client names are used to construct SQL statements but are not
  //          sanitized in any way. Therefore this method is susceptible to
  //          code injection unless the provided names are carefully vetted or
  //          sanitized.

  virtual int ExampleCount(const std::string& client_name,
                           const base::Time& start_time,
                           const base::Time& end_time) const;

  // Similar to ExampleCount but without time range, returns the count of all
  // examples in the client's table.
  virtual int ExampleCountForTesting(const std::string& client_name) const;

  // Deletes all examples in the specified client table. We expose only this
  // rudimentary functionality since small federated clients typically delete
  // all training examples at the end of a training session. More sophiscated
  // behavior can be added if it is later needed.
  //
  // WARNING: client names are used to construct SQL statements but are not
  //          sanitized in any way. Therefore this method is susceptible to
  //          code injection unless the provided names are carefully vetted or
  //          sanitized.
  virtual void DeleteAllExamples(const std::string& client_name);

  sqlite3* sqlite3_for_testing() const { return db_.get(); }

 private:
  // Typedef of sqlite3_exec callback, see sqlite doc:
  // https://sqlite.org/c3ref/exec.html.
  using SqliteCallback = int (*)(void* /*data*/,
                                 int /*count*/,
                                 char** /*row*/,
                                 char** /*names*/);

  // Sqlite error code and error message.
  struct ExecResult {
    int code;
    std::string error_msg;
  };

  // Counts the examples in the client's table that match the `where_clause` if
  // it's a valid SQL WHERE clause, or counts all the examples if `where_clause`
  // is an empty string. Returns 0 if database is closed or `where_clause` is
  // invalid.
  int ExampleCountInternal(const std::string& client_name,
                           const std::string& where_clause) const;

  // Returns true if the given table_name exists.
  bool TableExists(const std::string& table_name) const;

  // Returns true if the client's table is created without error.
  bool CreateClientTable(const std::string& client_name);

  // Returns true if the metatable exists.
  bool MetaTableExists() const;
  // Returns true if metatable is created without error.
  bool CreateMetaTable();

  // Executes sql.
  ExecResult ExecSql(const std::string& sql) const;
  ExecResult ExecSql(const std::string& sql,
                     SqliteCallback callback,
                     void* data) const;

  const base::FilePath db_path_;
  std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db_;
};

}  // namespace federated

#endif  // FEDERATED_EXAMPLE_DATABASE_H_
