// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_MOCK_EXAMPLE_DATABASE_H_
#define FEDERATED_MOCK_EXAMPLE_DATABASE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <unordered_set>

#include <base/time/time.h>
#include <gmock/gmock.h>
#include <sqlite3.h>

#include "federated/example_database.h"

namespace federated {

class MockExampleDatabase : public ExampleDatabase {
 public:
  using ExampleDatabase::ExampleDatabase;
  ~MockExampleDatabase() override = default;

  // Creates an example iterator reading from a table "fake_client" of the
  // form:
  //   -----------------------------------------------
  //   | serialized_example |       timestamp        |
  //   -----------------------------------------------
  //   | "example_1"        | unix epoch + 1 second  |
  //   -----------------------------------------------
  //   | "example_2"        | unix epoch + 2 seconds |
  //   -----------------------------------------------
  //   |                     ...                     |
  //   -----------------------------------------------
  //
  //   If start_time and end_time are properly specified, the iterator reads
  //   examples within the time range only.
  //   The returned sqlite3 database must outlive the iterator. If you release
  //   unique_ptr ownership, you must manually call sqlite3_close on the
  //   database pointer when you are done with it.
  static std::tuple<std::unique_ptr<sqlite3, decltype(&sqlite3_close)>,
                    Iterator>
  FakeIterator(int n);

  MOCK_METHOD(bool, Init, (const std::unordered_set<std::string>&), (override));
  MOCK_METHOD(bool, IsOpen, (), (const, override));
  MOCK_METHOD(bool, Close, (), (override));
  MOCK_METHOD(bool, CheckIntegrity, (), (const, override));
  MOCK_METHOD(std::optional<MetaRecord>,
              GetMetaRecord,
              (const std::string&),
              (const override));
  MOCK_METHOD(bool,
              UpdateMetaRecord,
              (const std::string&, const MetaRecord&),
              (const override));

  MOCK_METHOD(bool,
              DeleteOutdatedExamples,
              (const base::TimeDelta&),
              (const, override));
  MOCK_METHOD(bool,
              InsertExample,
              (const std::string&, const ExampleRecord&),
              (override));
  MOCK_METHOD(
      Iterator,
      GetIterator,
      (const std::string&, const base::Time&, const base::Time&, bool, size_t),
      (const, override));
  MOCK_METHOD(Iterator,
              GetIteratorForTesting,
              (const std::string&),
              (const, override));
  MOCK_METHOD(int,
              ExampleCount,
              (const std::string& client_name,
               const base::Time&,
               const base::Time&),
              (const, override));
  MOCK_METHOD(int,
              ExampleCountForTesting,
              (const std::string& client_name),
              (const, override));
  MOCK_METHOD(void,
              DeleteAllExamples,
              (const std::string& client_name),
              (override));
};

}  // namespace federated

#endif  // FEDERATED_MOCK_EXAMPLE_DATABASE_H_
