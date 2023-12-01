// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/storage_manager.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <google/protobuf/util/time_util.h>

#include "federated/example_database.h"
#include "federated/mock_example_database.h"
#include "federated/protos/cros_example_selector_criteria.pb.h"
#include "federated/test_utils.h"
#include "federated/utils.h"

namespace federated {
namespace {

using ::google::protobuf::util::TimeUtil;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Expectation;
using ::testing::ExpectationSet;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::Test;

}  // namespace

class StorageManagerTest : public Test {
 public:
  StorageManagerTest()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        example_database_(
            new StrictMock<MockExampleDatabase>(base::FilePath(""))),
        storage_manager_(new StorageManager()) {
    // criteria_ is minimally initialized.
    criteria_.set_task_name("test_task_name");
  }

  void SetUp() override {
    storage_manager_->set_example_database_for_testing(example_database_);
  }

  void TearDown() override {
    Mock::VerifyAndClearExpectations(example_database_);
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  MockExampleDatabase* const example_database_;
  const std::unique_ptr<StorageManager> storage_manager_;
  fcp::client::CrosExampleSelectorCriteria criteria_;
};

TEST_F(StorageManagerTest, ExampleRecieved) {
  EXPECT_CALL(*example_database_, IsOpen())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*example_database_, InsertExample("client", _))
      .WillRepeatedly(Return(true));

  // First call will fail due to the database !IsOpen;
  EXPECT_FALSE(storage_manager_->OnExampleReceived("client", "example"));
  EXPECT_TRUE(storage_manager_->OnExampleReceived("client", "example"));
}

// Tests that the databases example iterator is faithfully returned.
TEST_F(StorageManagerTest, ExampleStreaming) {
  base::Time end_timestamp = base::Time::Now();
  base::Time start_timestamp = end_timestamp - base::Days(20);
  EXPECT_CALL(*example_database_, IsOpen())
      .WillOnce(Return(false))
      .WillOnce(Return(true));

  EXPECT_CALL(*example_database_,
              ExampleCount("fake_client", start_timestamp, end_timestamp))
      .WillOnce(Return(kMinExampleCount));

  // Returns a valid number of examples, then returns absl::OutOfRangeError().
  auto db_and_it = MockExampleDatabase::FakeIterator(kMinExampleCount);
  EXPECT_CALL(*example_database_, GetIterator("fake_client", start_timestamp,
                                              end_timestamp, false, 0))
      .WillOnce(Return(ByMove(std::move(std::get<1>(db_and_it)))));

  // Fails due to !example_database_->IsOpen.
  EXPECT_EQ(storage_manager_->GetExampleIterator(
                "fake_client", "fake_task_identifier", criteria_),
            std::nullopt);
  std::optional<ExampleDatabase::Iterator> it =
      storage_manager_->GetExampleIterator("fake_client",
                                           "fake_task_identifier", criteria_);
  ASSERT_TRUE(it.has_value());

  // Expects the examples we specified.
  int count = 0;
  while (true) {
    const absl::StatusOr<ExampleRecord> record = it->Next();
    if (!record.ok()) {
      EXPECT_TRUE(absl::IsOutOfRange(record.status()));
      break;
    }

    EXPECT_EQ(record->id, count + 1);
    EXPECT_EQ(record->serialized_example,
              base::StringPrintf("example_%d", count + 1));
    EXPECT_EQ(record->timestamp, SecondsAfterEpoch(count + 1));

    ++count;
  }

  EXPECT_EQ(count, kMinExampleCount);
}

// Tests that minimum example limit is honored.
TEST_F(StorageManagerTest, ExampleStreamingMinimum) {
  EXPECT_CALL(*example_database_, IsOpen()).WillRepeatedly(Return(true));

  EXPECT_CALL(*example_database_, ExampleCount("fake_client", _, _))
      .WillOnce(Return(kMinExampleCount - 1))
      .WillOnce(Return(100));

  // Uses default kMinExampleCount
  EXPECT_EQ(storage_manager_->GetExampleIterator(
                "fake_client", "fake_task_identifier", criteria_),
            std::nullopt);

  // Uses `min_examples`
  criteria_.set_min_examples(101);
  EXPECT_EQ(storage_manager_->GetExampleIterator(
                "fake_client", "fake_task_identifier", criteria_),
            std::nullopt);
}

// Tests that when reject_used_examples, and metatable has record for this task,
// selection range is altered.
TEST_F(StorageManagerTest, CriteriaRejectUsedExamples) {
  EXPECT_CALL(*example_database_, IsOpen()).WillRepeatedly(Return(true));

  base::Time end_timestamp = base::Time::Now();
  base::Time default_start_timestamp = base::Time::Now() - base::Days(20);
  base::Time last_used_example_timestamp = base::Time::Now() - base::Hours(10);
  const MetaRecord meta_record = {"", 1, last_used_example_timestamp,
                                  base::Time::Now()};
  EXPECT_CALL(*example_database_, GetMetaRecord("fake_task_identifier"))
      .WillOnce(Return(std::nullopt))
      .WillOnce(Return(meta_record));

  criteria_.set_reject_used_examples(true);

  EXPECT_CALL(
      *example_database_,
      ExampleCount("fake_client", default_start_timestamp, end_timestamp))
      .WillOnce(Return(kMinExampleCount));

  EXPECT_CALL(*example_database_,
              GetIterator("fake_client", default_start_timestamp, end_timestamp,
                          false, 0))
      .WillOnce(Return(ByMove(ExampleDatabase::Iterator())));

  EXPECT_TRUE(
      storage_manager_
          ->GetExampleIterator("fake_client", "fake_task_identifier", criteria_)
          .has_value());

  EXPECT_CALL(
      *example_database_,
      ExampleCount("fake_client", last_used_example_timestamp, end_timestamp))
      .WillOnce(Return(kMinExampleCount));

  EXPECT_CALL(*example_database_,
              GetIterator("fake_client", last_used_example_timestamp,
                          end_timestamp, false, 0))
      .WillOnce(Return(ByMove(ExampleDatabase::Iterator())));

  EXPECT_TRUE(
      storage_manager_
          ->GetExampleIterator("fake_client", "fake_task_identifier", criteria_)
          .has_value());
}

TEST_F(StorageManagerTest, CriteriaOrderAndLimit) {
  EXPECT_CALL(*example_database_, IsOpen()).WillRepeatedly(Return(true));
  EXPECT_CALL(*example_database_, ExampleCount("fake_client", _, _))
      .WillRepeatedly(Return(kMinExampleCount));

  // By default, order = ascending, no limit(0);
  EXPECT_CALL(*example_database_,
              GetIterator("fake_client", _, _,
                          /*descending=*/false, /*limit=*/0))
      .WillOnce(Return(ByMove(ExampleDatabase::Iterator())));
  EXPECT_TRUE(
      storage_manager_
          ->GetExampleIterator("fake_client", "fake_task_identifier", criteria_)
          .has_value());

  // Respects the order setting.
  criteria_.set_order(
      fcp::client::CrosExampleSelectorCriteria::INSERTION_DESCENDING);
  EXPECT_CALL(*example_database_, GetIterator("fake_client", _, _,
                                              /*descending=*/true, /*limit=*/0))
      .WillOnce(Return(ByMove(ExampleDatabase::Iterator())));
  EXPECT_TRUE(
      storage_manager_
          ->GetExampleIterator("fake_client", "fake_task_identifier", criteria_)
          .has_value());

  // Respects the limit (max_examples) setting.
  criteria_.set_max_examples(100);
  EXPECT_CALL(*example_database_,
              GetIterator("fake_client", _, _,
                          /*descending=*/true, /*limit=*/100))
      .WillOnce(Return(ByMove(ExampleDatabase::Iterator())));
  EXPECT_TRUE(
      storage_manager_
          ->GetExampleIterator("fake_client", "fake_task_identifier", criteria_)
          .has_value());

  // Invalid limit setting is ignored.
  criteria_.set_max_examples(-1);
  EXPECT_CALL(*example_database_, GetIterator("fake_client", _, _,
                                              /*descending=*/true, /*limit=*/0))
      .WillOnce(Return(ByMove(ExampleDatabase::Iterator())));
  EXPECT_TRUE(
      storage_manager_
          ->GetExampleIterator("fake_client", "fake_task_identifier", criteria_)
          .has_value());
}

}  // namespace federated
