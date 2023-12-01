// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/example_database.h"

#include <cinttypes>
#include <string>
#include <unordered_set>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/strings/stringprintf.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gtest/gtest.h>
#include <sqlite3.h>

#include "federated/test_utils.h"
#include "federated/utils.h"

namespace federated {
namespace {

using ::testing::Test;

constexpr std::array<const char*, 2> kTestClients = {{
    "chromeos/test_client_1",  // table names are allowed to contain '/'.
    "test_client_2",
}};

// Opens a (potentially new) database at the given path and creates an example
// table with the given name.
int CreateExampleTableForTesting(const base::FilePath& db_path,
                                 const std::string& table) {
  constexpr char kCreateDatabaseSql[] = R"(
      CREATE TABLE '%s' (
        id         INTEGER PRIMARY KEY AUTOINCREMENT
                           NOT NULL,
        example    BLOB    NOT NULL,
        timestamp  INTEGER NOT NULL
      ))";

  sqlite3* db = nullptr;
  const int open_result = sqlite3_open(db_path.MaybeAsASCII().c_str(), &db);
  std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db_ptr(db, &sqlite3_close);

  if (open_result != SQLITE_OK) {
    return open_result;
  }

  const int create_result = sqlite3_exec(
      db_ptr.get(),
      base::StringPrintf(kCreateDatabaseSql, table.c_str()).c_str(), nullptr,
      nullptr, nullptr);
  return create_result;
}

// Adds `count` entries to `table` with entry i having serialized data
// "example_i" and timestamp "unix epoch + i seconds".
int PopulateTableForTesting(sqlite3* const db,
                            const std::string& table,
                            const int count) {
  for (int i = 1; i <= count; i++) {
    const std::string sql = base::StringPrintf(
        "INSERT INTO '%s' (example, timestamp) VALUES ('example_%d', "
        "%" PRId64 ")",
        table.c_str(), i, SecondsAfterEpoch(i).ToJavaTime());
    const int result = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    if (result != SQLITE_OK) {
      return result;
    }
  }

  return SQLITE_OK;
}

}  // namespace

// Checks sqlite3 has threading model = Serialized.
TEST(SqliteThreadSafe, Check) {
  EXPECT_EQ(1, sqlite3_threadsafe());
}

class ExampleDatabaseTest : public Test {
 public:
  ExampleDatabaseTest(const ExampleDatabaseTest&) = delete;
  ExampleDatabaseTest& operator=(const ExampleDatabaseTest&) = delete;

  const base::FilePath& temp_path() const { return temp_dir_.GetPath(); }

  // Prepares a database, table chromeos/test_client_1 has 100 examples (id from
  // 1 to 100), table test_client_2 is created by db_->Init() and is empty.
  bool CreateExampleDatabaseAndInitialize() {
    const base::FilePath db_path =
        temp_dir_.GetPath().Append(kDatabaseFileName);
    if (CreateExampleTableForTesting(db_path, "chromeos/test_client_1") !=
            SQLITE_OK ||
        !base::PathExists(db_path)) {
      LOG(ERROR) << "Failed to create initial database";
      return false;
    }

    const std::unordered_set<std::string> clients(kTestClients.begin(),
                                                  kTestClients.end());
    db_ = std::make_unique<ExampleDatabase>(db_path);
    if (!db_->Init(clients) || !db_->IsOpen() || !db_->CheckIntegrity() ||
        PopulateTableForTesting(db_->sqlite3_for_testing(),
                                "chromeos/test_client_1", 100) != SQLITE_OK) {
      LOG(ERROR) << "Failed to initialize or check integrity of db_";
      return false;
    }

    return base::PathExists(db_path);
  }

 protected:
  ExampleDatabaseTest() = default;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }
  void TearDown() override { ASSERT_TRUE(temp_dir_.Delete()); }

  base::test::TaskEnvironment task_environment_;
  base::ScopedTempDir temp_dir_;
  std::unique_ptr<ExampleDatabase> db_;
};

// This test runs the same steps as CreateExampleDatabaseAndInitialize, but
// checks step by step.
TEST_F(ExampleDatabaseTest, CreateDatabase) {
  // Prepares a database file.
  const base::FilePath db_path = temp_path().Append(kDatabaseFileName);
  ASSERT_EQ(CreateExampleTableForTesting(db_path, "chromeos/test_client_1"),
            SQLITE_OK);
  EXPECT_TRUE(base::PathExists(db_path));

  // Initializes the db and checks integrity.
  const std::unordered_set<std::string> clients(kTestClients.begin(),
                                                kTestClients.end());
  ExampleDatabase db(db_path);
  EXPECT_TRUE(db.Init(clients));
  EXPECT_TRUE(db.IsOpen());
  EXPECT_TRUE(db.CheckIntegrity());

  // Populates examples.
  EXPECT_EQ(PopulateTableForTesting(db.sqlite3_for_testing(),
                                    "chromeos/test_client_1", 100),
            SQLITE_OK);

  // Closes it.
  EXPECT_TRUE(db.Close());
}

// Test that initialization handles internal SQL errors.
TEST_F(ExampleDatabaseTest, CreateDatabaseMalformed) {
  // Prepares a database file.
  const base::FilePath db_path = temp_path().Append(kDatabaseFileName);
  ExampleDatabase db(db_path);

  // Inject broken SQL statement. Table names starting with "sqlite_" are
  // reserved and not allowed.
  EXPECT_FALSE(db.Init({"sqlite_chromeos/test_client_1"}));

  EXPECT_FALSE(db.IsOpen());
  EXPECT_FALSE(db.CheckIntegrity());
  EXPECT_FALSE(db.InsertExample("sqlite_chromeos/test_client_1",
                                {-1, "example_1", SecondsAfterEpoch(1)}));

  EXPECT_TRUE(db.Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadNonEmpty) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  int count = 0;
  ExampleDatabase::Iterator it =
      db_->GetIteratorForTesting("chromeos/test_client_1");
  while (true) {
    const absl::StatusOr<ExampleRecord> record = it.Next();
    if (!record.ok()) {
      EXPECT_TRUE(absl::IsOutOfRange(record.status()));
      break;
    }

    EXPECT_EQ(record->id, count + 1);
    EXPECT_EQ(record->serialized_example,
              base::StringPrintf("example_%d", count + 1));
    EXPECT_EQ(record->timestamp, SecondsAfterEpoch(count + 1));
    count++;
  }

  EXPECT_EQ(count, 100);
  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadNonEmptyWithTimeRange) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  int count = 0;
  int expected_id = 11;
  // Start_timestamp is not included, therefore expected_id starts from 11
  // rather than 10;
  ExampleDatabase::Iterator it = db_->GetIterator(
      "chromeos/test_client_1", SecondsAfterEpoch(10), SecondsAfterEpoch(30));
  while (true) {
    const absl::StatusOr<ExampleRecord> record = it.Next();
    if (!record.ok()) {
      EXPECT_TRUE(absl::IsOutOfRange(record.status()));
      break;
    }

    EXPECT_EQ(record->id, expected_id);
    EXPECT_EQ(record->serialized_example,
              base::StringPrintf("example_%d", expected_id));
    EXPECT_EQ(record->timestamp, SecondsAfterEpoch(expected_id));
    expected_id++;
    count++;
  }

  EXPECT_EQ(count, 20);
  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadWithLimit) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  int count = 0;
  int expected_id = 11;
  // Start_timestamp is not included, therefore expected_id starts from 11
  // rather than 10;
  ExampleDatabase::Iterator it = db_->GetIterator(
      "chromeos/test_client_1", SecondsAfterEpoch(10), SecondsAfterEpoch(30),
      /*descending=*/false, /*limit=*/10);
  while (true) {
    const absl::StatusOr<ExampleRecord> record = it.Next();
    if (!record.ok()) {
      EXPECT_TRUE(absl::IsOutOfRange(record.status()));
      break;
    }

    EXPECT_EQ(record->id, expected_id);
    EXPECT_EQ(record->serialized_example,
              base::StringPrintf("example_%d", expected_id));
    EXPECT_EQ(record->timestamp, SecondsAfterEpoch(expected_id));
    expected_id++;
    count++;
  }

  EXPECT_EQ(count, 10);
  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadOrderDesc) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  int count = 0;
  int expected_id = 30;
  // Start_timestamp is not included, therefore expected_id starts from 11
  // rather than 10;
  ExampleDatabase::Iterator it = db_->GetIterator(
      "chromeos/test_client_1", SecondsAfterEpoch(10), SecondsAfterEpoch(30),
      /*descending=*/true);
  while (true) {
    const absl::StatusOr<ExampleRecord> record = it.Next();
    if (!record.ok()) {
      EXPECT_TRUE(absl::IsOutOfRange(record.status()));
      break;
    }

    EXPECT_EQ(record->id, expected_id);
    EXPECT_EQ(record->serialized_example,
              base::StringPrintf("example_%d", expected_id));
    EXPECT_EQ(record->timestamp, SecondsAfterEpoch(expected_id));
    expected_id--;
    count++;
  }

  EXPECT_EQ(count, 20);
  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadDangle) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());
  ExampleDatabase::Iterator it =
      db_->GetIteratorForTesting("chromeos/test_client_1");

  // The iterator sqlite query is ongoing.
  EXPECT_FALSE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadAbort) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());
  ExampleDatabase::Iterator it =
      db_->GetIteratorForTesting("chromeos/test_client_1");

  // Iterate through 3 of the 100 examples.
  for (int i = 1; i <= 3; ++i) {
    const absl::StatusOr<ExampleRecord> record = it.Next();
    ASSERT_TRUE(record.ok());

    EXPECT_EQ(record->id, i);
    EXPECT_EQ(record->serialized_example, base::StringPrintf("example_%d", i));
    EXPECT_EQ(record->timestamp, SecondsAfterEpoch(i));
  }

  it.Close();
  EXPECT_TRUE(db_->Close());
}

// Example of attaching an example iterator to the life of a callback, which
// could be useful with our library interface.
TEST_F(ExampleDatabaseTest, DatabaseReadCallback) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Using a manual scope tests that the iterator is successfully closed when
  // the callback is destroyed.
  {
    // Create a callback that owns an iterator.
    base::RepeatingCallback<void(int)> cb = base::BindRepeating(
        [](ExampleDatabase::Iterator* const it, const int i) {
          const absl::StatusOr<ExampleRecord> record = it->Next();
          ASSERT_TRUE(record.ok());
          EXPECT_EQ(record->id, i);
          EXPECT_EQ(record->serialized_example,
                    base::StringPrintf("example_%d", i));
          EXPECT_EQ(record->timestamp, SecondsAfterEpoch(i));
        },
        base::Owned(new ExampleDatabase::Iterator(
            db_->GetIteratorForTesting("chromeos/test_client_1"))));

    // Run the callback to test sequential use works.
    for (int i = 1; i <= 3; ++i) {
      cb.Run(i);
    }

    // As the sqlite query is ongoing, the callback must correctly close the
    // iterator here as it falls out of scope.
  }

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadConcurrent) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Add 50 examples to the second table.
  ASSERT_EQ(
      PopulateTableForTesting(db_->sqlite3_for_testing(), "test_client_2", 50),
      SQLITE_OK);

  ExampleDatabase::Iterator it[] = {
      db_->GetIteratorForTesting("chromeos/test_client_1"),
      db_->GetIteratorForTesting("chromeos/test_client_1"),
      db_->GetIteratorForTesting("test_client_2"),
  };
  int count[] = {0, 0, 0};
  bool going[] = {true, true, true};

  while (going[0] || going[1] || going[2]) {
    for (int i = 0; i < 3; ++i) {
      if (!going[i]) {
        continue;
      }

      const absl::StatusOr<ExampleRecord> record = it[i].Next();
      if (!record.ok()) {
        EXPECT_TRUE(absl::IsOutOfRange(record.status()));
        going[i] = false;
        continue;
      }

      EXPECT_EQ(record->id, count[i] + 1);
      EXPECT_EQ(record->serialized_example,
                base::StringPrintf("example_%d", count[i] + 1));
      EXPECT_EQ(record->timestamp, SecondsAfterEpoch(count[i] + 1));
      count[i]++;
    }
  }

  EXPECT_EQ(count[0], 100);
  EXPECT_EQ(count[1], 100);
  EXPECT_EQ(count[2], 50);
  EXPECT_TRUE(db_->Close());
}

// Tests that it's safe to have write requests when example iterators are live.
TEST_F(ExampleDatabaseTest, DatabaseReadAndWriteConcurrentWithTimeRange) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Add 50 examples to the second table.
  ASSERT_EQ(
      PopulateTableForTesting(db_->sqlite3_for_testing(), "test_client_2", 50),
      SQLITE_OK);

  ExampleDatabase::Iterator it[] = {
      db_->GetIterator("chromeos/test_client_1", SecondsAfterEpoch(0),
                       SecondsAfterEpoch(30)),
      db_->GetIterator("chromeos/test_client_1", SecondsAfterEpoch(50),
                       SecondsAfterEpoch(90)),
      db_->GetIterator("test_client_2", SecondsAfterEpoch(0),
                       SecondsAfterEpoch(50)),
  };
  int count[] = {0, 0, 0};
  int expected_id[] = {1, 51, 1};
  bool going[] = {true, true, true};

  // This makes newly added examples not interact with existing iterators.
  int64_t current_timestamp = 101;
  while (going[0] || going[1] || going[2]) {
    for (int i = 0; i < 3; ++i) {
      if (!going[i]) {
        continue;
      }

      const absl::StatusOr<ExampleRecord> record = it[i].Next();
      if (!record.ok()) {
        EXPECT_TRUE(absl::IsOutOfRange(record.status()));
        going[i] = false;
        continue;
      }

      EXPECT_EQ(record->id, expected_id[i]);
      EXPECT_EQ(record->serialized_example,
                base::StringPrintf("example_%d", expected_id[i]));
      EXPECT_EQ(record->timestamp, SecondsAfterEpoch(expected_id[i]));

      ExampleRecord record_to_insert = {-1, "manual_example",
                                        SecondsAfterEpoch(current_timestamp++)};

      EXPECT_TRUE(
          db_->InsertExample("chromeos/test_client_1", record_to_insert));
      // {-1, "manual_example", SecondsAfterEpoch(current_timestamp++)}));
      EXPECT_TRUE(db_->InsertExample("test_client_2", record_to_insert));
      // {-1, "manual_example", SecondsAfterEpoch(current_timestamp++)}));
      count[i]++;
      expected_id[i]++;
    }
  }

  EXPECT_EQ(count[0], 30);
  EXPECT_EQ(count[1], 40);
  EXPECT_EQ(count[2], 50);
  EXPECT_TRUE(db_->Close());
}

// Tests that it's safe to have write requests when example iterators are live
// on other threads.
TEST_F(ExampleDatabaseTest, DatabaseReadAndWriteConcurrentMultipleThread) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Add 50 examples to the second table.
  ASSERT_EQ(
      PopulateTableForTesting(db_->sqlite3_for_testing(), "test_client_2", 50),
      SQLITE_OK);

  std::string client_names[] = {"chromeos/test_client_1",
                                "chromeos/test_client_1", "test_client_2"};
  int count[] = {0, 0, 0};
  int start_second[] = {1, 51, 1};
  int end_second[] = {30, 90, 50};

  base::RepeatingCallback<void()> insert_cb = base::BindRepeating(
      [](ExampleDatabase* const db) {
        EXPECT_TRUE(
            db->InsertExample("chromeos/test_client_1",
                              {-1, "manual_example", SecondsAfterEpoch(500)}));
        EXPECT_TRUE(db->InsertExample(
            "test_client_2", {-1, "manual_example", SecondsAfterEpoch(500)}));
      },
      db_.get());

  // Starts 3 iterators, 2 for chromeos/test_client_1, 1 for test_client_2 on
  // different threads and reads examples from them. Meanwhile posts several
  // insert tasks to multiple threads.
  for (int i = 0; i < 3; i++) {
    base::ThreadPool::PostTask(
        FROM_HERE,
        base::BindOnce(
            [](ExampleDatabase* const db, const std::string& client_name,
               const int start_second, const int end_second, int* const count) {
              ExampleDatabase::Iterator it = db->GetIterator(
                  client_name, SecondsAfterEpoch(start_second - 1),
                  SecondsAfterEpoch(end_second));
              while (true) {
                const absl::StatusOr<ExampleRecord> record = it.Next();
                if (!record.ok()) {
                  EXPECT_TRUE(absl::IsOutOfRange(record.status()));
                  break;
                }

                EXPECT_EQ(record->id, *count + start_second);
                EXPECT_EQ(
                    record->serialized_example,
                    base::StringPrintf("example_%d", *count + start_second));
                EXPECT_EQ(record->timestamp,
                          SecondsAfterEpoch(*count + start_second));
                (*count)++;
              }
            },
            db_.get(), client_names[i], start_second[i], end_second[i],
            &count[i]));

    for (int j = 0; j < 10; j++) {
      base::ThreadPool::PostTask(FROM_HERE, insert_cb);
    }
  }

  task_environment_.RunUntilIdle();

  // All iterator are expected to get correct numbers of examples.
  EXPECT_EQ(count[0], 30);
  EXPECT_EQ(count[1], 40);
  EXPECT_EQ(count[2], 50);

  // All insert requests should succeed, hence new example counts.
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 130);
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 80);

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DatabaseReadMalformed) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Inject malformed SQL code.
  ExampleDatabase::Iterator it_invalid =
      db_->GetIteratorForTesting("chromeos/test_client_1\"");
  EXPECT_TRUE(absl::IsInvalidArgument(it_invalid.Next().status()));

  // Now try a valid read.
  ExampleDatabase::Iterator it_valid =
      db_->GetIteratorForTesting("chromeos/test_client_1");
  const absl::StatusOr<ExampleRecord> record = it_valid.Next();
  EXPECT_TRUE(record.ok());
  EXPECT_EQ(record->id, 1);
  EXPECT_EQ(record->serialized_example, "example_1");
  EXPECT_EQ(record->timestamp, SecondsAfterEpoch(1));
  it_valid.Close();

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, InsertExample) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Before inserting, table test_client_2 is empty.
  EXPECT_TRUE(absl::IsOutOfRange(
      db_->GetIteratorForTesting("test_client_2").Next().status()));

  // After inserting, iteration will succeed 1 time.
  EXPECT_TRUE(db_->InsertExample("test_client_2",
                                 {-1, "manual_example", SecondsAfterEpoch(0)}));

  ExampleDatabase::Iterator it = db_->GetIteratorForTesting("test_client_2");
  const absl::StatusOr<ExampleRecord> result = it.Next();
  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result->id, 1);  // First entry in the client 2 table.
  EXPECT_EQ(result->serialized_example, "manual_example");
  EXPECT_EQ(result->timestamp, SecondsAfterEpoch(0));
  EXPECT_TRUE(absl::IsOutOfRange(it.Next().status()));

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, InsertExampleBad) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Client 3 table doesn't exist.
  EXPECT_FALSE(db_->InsertExample("test_client_3", ExampleRecord()));
  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, InsertExampleMalformed) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Inject malformed SQL code.
  EXPECT_FALSE(db_->InsertExample("chromeos/test_client_1\"",
                                  {-1, "example_1", SecondsAfterEpoch(1)}));

  // Now try a valid insertion.
  EXPECT_TRUE(db_->InsertExample("test_client_2",
                                 {-1, "example_2", SecondsAfterEpoch(2)}));
  ExampleDatabase::Iterator it = db_->GetIteratorForTesting("test_client_2");
  const absl::StatusOr<ExampleRecord> record = it.Next();
  EXPECT_TRUE(record.ok());
  EXPECT_EQ(record->id, 1);
  EXPECT_EQ(record->serialized_example, "example_2");
  EXPECT_EQ(record->timestamp, SecondsAfterEpoch(2));
  EXPECT_TRUE(absl::IsOutOfRange(it.Next().status()));

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, CountExamples) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 100);
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 0);

  // Client table 3 doesn't exist.
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_3"), 0);
}

TEST_F(ExampleDatabaseTest, CountExamplesWithTimeRange) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Start_timestamp is not included.
  EXPECT_EQ(db_->ExampleCount("chromeos/test_client_1", SecondsAfterEpoch(0),
                              SecondsAfterEpoch(30)),
            30);
  EXPECT_EQ(db_->ExampleCount("chromeos/test_client_1", SecondsAfterEpoch(10),
                              SecondsAfterEpoch(30)),
            20);
  // The max timestamp in table is 100.
  EXPECT_EQ(db_->ExampleCount("chromeos/test_client_1", SecondsAfterEpoch(10),
                              SecondsAfterEpoch(200)),
            90);
}

TEST_F(ExampleDatabaseTest, CountExamplesMalformed) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Inject invalid SQL code.
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1\""), 0);

  // Now try a valid read.
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 100);
}

TEST_F(ExampleDatabaseTest, DeleteExamples) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Populated table.
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 100);
  db_->DeleteAllExamples("chromeos/test_client_1");
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 0);

  // Unpopulated table.
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 0);
  db_->DeleteAllExamples("test_client_2");
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 0);

  // Newly-populated table.
  db_->InsertExample("test_client_2", {-1, "example_1", SecondsAfterEpoch(1)});
  db_->InsertExample("test_client_2", {-1, "example_2", SecondsAfterEpoch(2)});
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 2);
  db_->DeleteAllExamples("test_client_2");
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 0);

  db_->InsertExample("test_client_2", {-1, "example_3", SecondsAfterEpoch(3)});
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 1);
  db_->DeleteAllExamples("test_client_2");
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_2"), 0);

  // Missing table.
  db_->DeleteAllExamples("test_client_3");
  EXPECT_EQ(db_->ExampleCountForTesting("test_client_3"), 0);

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DeleteExamplesMalformed) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  // Inject invalid SQL code.
  db_->DeleteAllExamples("chromeos/test_client_1\"");

  // Now test valid deletion still works.
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 100);
  db_->DeleteAllExamples("chromeos/test_client_1");
  EXPECT_EQ(db_->ExampleCountForTesting("chromeos/test_client_1"), 0);

  EXPECT_TRUE(db_->Close());
}

TEST_F(ExampleDatabaseTest, DeleteOutdatedExamples) {
  // Prepares the db file, in table chromeos/test_client_1 there are 100
  // outdated examples with timestamp = SecondsAfterEpoch(*), and one example
  // with timestamp = Now();
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());
  ASSERT_TRUE(db_->InsertExample("chromeos/test_client_1",
                                 {-1, "manual_example", base::Time::Now()}));
  ASSERT_TRUE(db_->Close());

  // Creates a new ExampleDatabase instance that loads this db, and calls
  // `DeleteOutdatedExamples` to delete all expired examples.
  const base::FilePath db_path = temp_path().Append(kDatabaseFileName);
  EXPECT_TRUE(base::PathExists(db_path));

  const std::unordered_set<std::string> clients(kTestClients.begin(),
                                                kTestClients.end());
  ExampleDatabase db(db_path);
  EXPECT_TRUE(db.Init(clients));
  EXPECT_TRUE(db.IsOpen());
  EXPECT_TRUE(db.CheckIntegrity());

  EXPECT_TRUE(db.DeleteOutdatedExamples(base::Days(10)));

  // Now only the manual example remains in the table.
  EXPECT_EQ(1, db.ExampleCountForTesting("chromeos/test_client_1"));
  ExampleDatabase::Iterator it =
      db.GetIteratorForTesting("chromeos/test_client_1");
  auto record = it.Next();
  EXPECT_TRUE(record.ok());
  EXPECT_EQ(record->id, 101);
  EXPECT_EQ(record->serialized_example, "manual_example");

  record = it.Next();
  EXPECT_TRUE(absl::IsOutOfRange(record.status()));

  EXPECT_TRUE(db.Close());
}

// Tests meta table can be queried and updated successfully.
TEST_F(ExampleDatabaseTest, MetaTableTest) {
  ASSERT_TRUE(CreateExampleDatabaseAndInitialize());

  const std::string identifier = "test_identifier";

  // No record in meta table, gets nullopt.
  EXPECT_EQ(db_->GetMetaRecord(identifier), std::nullopt);

  // Inserts new record.
  EXPECT_TRUE(db_->UpdateMetaRecord(
      identifier, {identifier, 1, SecondsAfterEpoch(1), SecondsAfterEpoch(5)}));
  auto meta_record = db_->GetMetaRecord(identifier);
  EXPECT_TRUE(meta_record.has_value());
  EXPECT_EQ(meta_record.value().last_used_example_id, 1);
  EXPECT_EQ(meta_record.value().last_used_example_timestamp,
            SecondsAfterEpoch(1));
  EXPECT_EQ(meta_record.value().timestamp, SecondsAfterEpoch(5));

  // Updates existing record.
  EXPECT_TRUE(db_->UpdateMetaRecord(
      identifier,
      {identifier, 2, SecondsAfterEpoch(2), SecondsAfterEpoch(100)}));
  meta_record = db_->GetMetaRecord(identifier);
  EXPECT_TRUE(meta_record.has_value());
  EXPECT_EQ(meta_record.value().last_used_example_id, 2);
  EXPECT_EQ(meta_record.value().last_used_example_timestamp,
            SecondsAfterEpoch(2));
  EXPECT_EQ(meta_record.value().timestamp, SecondsAfterEpoch(100));

  EXPECT_TRUE(db_->Close());
}

}  // namespace federated
