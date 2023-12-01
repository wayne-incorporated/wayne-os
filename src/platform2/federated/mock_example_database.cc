// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/mock_example_database.h"

#include <cinttypes>
#include <utility>

#include <base/check_op.h>
#include <base/strings/stringprintf.h>

#include "federated/test_utils.h"

namespace federated {

namespace {
constexpr char kCreateTableSql[] =
    "CREATE TABLE fake_client ("
    "  id         INTEGER PRIMARY KEY AUTOINCREMENT"
    "                     NOT NULL,"
    "  example    BLOB    NOT NULL,"
    "  timestamp  INTEGER NOT NULL"
    ")";
}  // namespace

std::tuple<std::unique_ptr<sqlite3, decltype(&sqlite3_close)>,
           ExampleDatabase::Iterator>
MockExampleDatabase::FakeIterator(const int n) {
  // Create in-memory database.
  sqlite3* db;
  const int result = sqlite3_open(":memory:", &db);
  auto db_ptr =
      std::unique_ptr<sqlite3, decltype(&sqlite3_close)>(db, &sqlite3_close);
  CHECK_EQ(result, SQLITE_OK);

  // Create fake client table.
  CHECK_EQ(sqlite3_exec(db, kCreateTableSql, nullptr, nullptr, nullptr),
           SQLITE_OK);

  // Insert the specified examples.
  for (int i = 1; i <= n; ++i) {
    const std::string sql_code = base::StringPrintf(
        "INSERT INTO fake_client (example, timestamp) VALUES "
        "('example_%d', %" PRId64 ")",
        i, SecondsAfterEpoch(i).ToJavaTime());

    CHECK_EQ(sqlite3_exec(db, sql_code.c_str(), nullptr, nullptr, nullptr),
             SQLITE_OK);
  }

  return std::make_tuple(
      std::move(db_ptr),
      Iterator(db, "fake_client", base::Time(), base::Time(), false, 0));
}

}  // namespace federated
