// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/resources/enqueuing_record_tallier.h"

#include <cstdint>
#include <string>
#include <tuple>
#include <utility>

#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/proto/record.pb.h"
#include "missive/util/statusor.h"

using ::testing::Eq;

namespace reporting {

class FakeEnqueuingRecordTallier : public EnqueuingRecordTallier {
 public:
  explicit FakeEnqueuingRecordTallier(base::TimeDelta interval)
      : EnqueuingRecordTallier(interval) {}

  // Sets what the fake |GetCurrentWallTime| returns.
  void SetCurrentWallTime(StatusOr<uint64_t> wall_time) {
    fake_wall_time_ = std::move(wall_time);
  }

  // Tallies the same record multiple times
  void TallyTimes(const Record& record, uint64_t times) {
    for (uint64_t i = 0; i < times; ++i) {
      Tally(record);
    }
  }

  // Resets the last recorded wall clock
  void ResetLastWallTime() { last_wall_time_ = GetCurrentWallTime(); }

 private:
  // Fake method to get current wall time.
  StatusOr<uint64_t> GetCurrentWallTime() const override {
    return fake_wall_time_;
  }

  // The value that the fake |GetCurrentWallTime| returns.
  StatusOr<uint64_t> fake_wall_time_;
};

class EnqueuingRecordTallierTest : public ::testing::Test {
 protected:
  void SetUp() override {
    tallier_.SetCurrentWallTime(0U);  // All tests start with time 0
    tallier_.ResetLastWallTime();
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  // The record for testing
  const Record kRecord{InitializeRecord()};
  const uint64_t kRecordSize{kRecord.ByteSizeLong()};
  // Interval for |EnqueuingRecordTallier|.
  const base::TimeDelta kInterval{base::Seconds(40)};
  // Fake |EnqueuingRecordTallier| for test.
  FakeEnqueuingRecordTallier tallier_{kInterval};

 private:
  // Initialize a record for testing purpose
  Record InitializeRecord() {
    Record record;
    record.set_data(std::string(100, 'A'));
    return record;
  }
};

TEST_F(EnqueuingRecordTallierTest, SucceedWhenNormal) {
  // Succeed when the situation is normal
  constexpr uint64_t kNumRecords = 3U;
  constexpr uint64_t kWallTime = 10U;
  tallier_.TallyTimes(kRecord, kNumRecords);
  tallier_.SetCurrentWallTime(kWallTime);

  // Move forward time
  ASSERT_FALSE(tallier_.GetAverage().has_value());
  task_environment_.FastForwardBy(kInterval - base::Seconds(1));
  task_environment_.RunUntilIdle();
  ASSERT_FALSE(tallier_.GetAverage().has_value());
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();

  const auto rate = tallier_.GetAverage();
  ASSERT_TRUE(rate.has_value());
  ASSERT_THAT(rate.value(), Eq(kNumRecords * kRecordSize / kWallTime));
}

TEST_F(EnqueuingRecordTallierTest, AssumeOneWhenNoTimeDifference) {
  // If time has passed for less than one second, assume one second has passed
  constexpr uint64_t kNumRecords = 2U;
  constexpr uint64_t kWallTime = 0U;  // time has elapsed for less than 1 sec
  tallier_.TallyTimes(kRecord, kNumRecords);
  tallier_.SetCurrentWallTime(kWallTime);

  // Move forward time
  ASSERT_FALSE(tallier_.GetAverage().has_value());
  task_environment_.FastForwardBy(kInterval - base::Seconds(1));
  task_environment_.RunUntilIdle();
  ASSERT_FALSE(tallier_.GetAverage().has_value());
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();

  const auto rate = tallier_.GetAverage();
  ASSERT_TRUE(rate.has_value());
  ASSERT_THAT(rate.value(), Eq(kNumRecords * kRecordSize / 1U));
}

TEST_F(EnqueuingRecordTallierTest, FailedToGetCurrentWallTime) {
  // Failed to get current wall time
  constexpr uint64_t kNumRecords = 2U;
  const Status kWallTime(error::UNKNOWN, "Failed to get wall time");
  tallier_.TallyTimes(kRecord, kNumRecords);
  tallier_.SetCurrentWallTime(kWallTime);

  // kWallTime dictates the return value of |GetAverage|.
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
  const auto rate = tallier_.GetAverage();
  ASSERT_FALSE(rate.has_value());
}

TEST_F(EnqueuingRecordTallierTest, FailedToGetLastWallTime) {
  // Failed to get last wall time
  constexpr uint64_t kNumRecords = 30U;
  const Status kFailedWallTime(error::UNKNOWN, "Failed to get wall time");
  constexpr uint64_t kSuccessfulWallTime = 40U;

  tallier_.SetCurrentWallTime(kFailedWallTime);
  tallier_.ResetLastWallTime();

  // The erroneous last wall time dictates the return value of |GetAverage|.
  tallier_.SetCurrentWallTime(kSuccessfulWallTime);
  tallier_.TallyTimes(kRecord, kNumRecords);
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
  ASSERT_FALSE(tallier_.GetAverage().has_value());

  // One more time things should be back to normal.
  tallier_.TallyTimes(kRecord, kNumRecords);
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
  const auto rate = tallier_.GetAverage();
  ASSERT_TRUE(rate.has_value());
  ASSERT_THAT(rate.value(), Eq(kNumRecords * kRecordSize / 1U));
}
}  // namespace reporting
