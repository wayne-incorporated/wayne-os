// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vmm_swap_usage_policy.h"

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/time/time.h>
#include <gtest/gtest.h>

#include "vm_concierge/vmm_swap_policy.pb.h"

namespace vm_tools::concierge {
TEST(VmmSwapUsagePolicyTest, PredictDuration) {
  VmmSwapUsagePolicy policy;

  EXPECT_TRUE(policy.PredictDuration().is_zero());
}

TEST(VmmSwapUsagePolicyTest, PredictDurationJustLogLongTimeAgo) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(29));
  policy.OnDisabled(now - base::Days(28) - base::Seconds(1));

  EXPECT_TRUE(policy.PredictDuration(now).is_zero());
}

TEST(VmmSwapUsagePolicyTest, PredictDurationEnabledFullTime) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(29));

  EXPECT_EQ(policy.PredictDuration(now), base::Days(28 + 21 + 14 + 7) / 4);
}

TEST(VmmSwapUsagePolicyTest, PredictDurationWithMissingEnabledRecord) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(29));
  policy.OnDisabled(now - base::Days(29) + base::Minutes(50));
  // This enabled record is skipped.
  policy.OnEnabled(now - base::Days(29) + base::Minutes(30));

  EXPECT_EQ(policy.PredictDuration(now), base::Days(28 + 21 + 14 + 7) / 4);
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLessThan1WeekDataWhileDisabled) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(7) + base::Hours(1));
  policy.OnDisabled(now - base::Days(7) + base::Hours(10));

  policy.OnEnabled(now - base::Days(6));
  policy.OnDisabled(now - base::Days(6) + base::Hours(1));

  // The latest enabled duration * 2
  EXPECT_EQ(policy.PredictDuration(now), base::Hours(2));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLessThan1WeekDataWhileEnabled) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(6));
  policy.OnDisabled(now - base::Days(6) + base::Hours(1));

  policy.OnEnabled(now - base::Minutes(10));

  // The latest enabled duration * 2
  EXPECT_EQ(policy.PredictDuration(now), base::Minutes(20));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationJust1WeekData) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(7));
  policy.OnDisabled(now - base::Days(7) + base::Hours(10));

  policy.OnEnabled(now - base::Days(6));

  // The latest enabled duration
  EXPECT_EQ(policy.PredictDuration(now), base::Hours(10));
}

TEST(VmmSwapUsagePolicyTest,
     PredictDurationLessThan1WeekDataWhileMultipleEnabled) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Minutes(50));
  policy.OnDisabled(now - base::Minutes(30));
  policy.OnEnabled(now - base::Minutes(5));

  // The latest enabled duration in 1 hour * 2.
  EXPECT_EQ(policy.PredictDuration(now), base::Minutes(40));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLessThan2WeekData) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(10));
  policy.OnDisabled(now - base::Days(8));
  // Enabled record across the point 1 week ago.
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(1));
  policy.OnEnabled(now - base::Minutes(30));

  EXPECT_EQ(policy.PredictDuration(now), base::Hours(1));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLessThan3WeekData) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(14) - base::Hours(2));
  policy.OnDisabled(now - base::Days(14) + base::Hours(4));
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(6));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of 4 + 6 hours.
  EXPECT_EQ(policy.PredictDuration(now), base::Hours(5));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLessThan4WeekData) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(21) - base::Hours(2));
  policy.OnDisabled(now - base::Days(21) + base::Hours(2));
  policy.OnEnabled(now - base::Days(14) - base::Hours(2));
  policy.OnDisabled(now - base::Days(14) + base::Hours(4));
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(6));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of 2 + 4 + 6 hours.
  EXPECT_EQ(policy.PredictDuration(now), base::Hours(4));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationFullData) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(28) + base::Hours(16));
  policy.OnEnabled(now - base::Days(21) - base::Hours(2));
  policy.OnDisabled(now - base::Days(21) + base::Hours(2));
  policy.OnEnabled(now - base::Days(14) - base::Hours(2));
  policy.OnDisabled(now - base::Days(14) + base::Hours(4));
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(6));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of 16 + 2 + 4 + 6 hours.
  EXPECT_EQ(policy.PredictDuration(now), base::Hours(7));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationFullDataWithEmptyWeeks) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(28) + base::Hours(16));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of 16 + 0 + 0 + 0 hours.
  EXPECT_EQ(policy.PredictDuration(now), base::Hours(4));
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLong2WeeksData4Weeks) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(21) + base::Hours(3));
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(6));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of (7days + 3hours) + 3hours + 0 + 6hours.
  EXPECT_EQ(policy.PredictDuration(now), (base::Days(7) + base::Hours(12)) / 4);
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLong3WeeksData4Weeks) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(14) + base::Hours(3));
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(6));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of (14days + 3hours) + (7days+3hours) + 3hours + 6hours.
  EXPECT_EQ(policy.PredictDuration(now),
            (base::Days(21) + base::Hours(15)) / 4);
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLong4WeeksData4Weeks) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(3));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of (21days + 3hours) + (14days+3hours) + (7days+3hours) + 3hours.
  EXPECT_EQ(policy.PredictDuration(now),
            (base::Days(42) + base::Hours(12)) / 4);
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLongData3Weeks) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(28) + base::Hours(3));
  policy.OnEnabled(now - base::Days(21) - base::Hours(2));
  policy.OnDisabled(now - base::Days(14) + base::Hours(3));
  policy.OnEnabled(now - base::Days(7) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(6));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of  3hours + (7days + 3hours) + 3hours + 6hours.
  EXPECT_EQ(policy.PredictDuration(now), (base::Days(7) + base::Hours(15)) / 4);
}

TEST(VmmSwapUsagePolicyTest, PredictDurationLongData2Weeks) {
  VmmSwapUsagePolicy policy;
  base::Time now = base::Time::Now();

  policy.OnEnabled(now - base::Days(28) - base::Hours(2));
  policy.OnDisabled(now - base::Days(28) + base::Hours(3));
  policy.OnEnabled(now - base::Days(14) - base::Hours(2));
  policy.OnDisabled(now - base::Days(7) + base::Hours(3));
  policy.OnEnabled(now - base::Minutes(30));

  // Average of  3hours + 0 + (7days + 3hours) + 3hours.
  EXPECT_EQ(policy.PredictDuration(now), (base::Days(7) + base::Hours(9)) / 4);
}

TEST(VmmSwapUsagePolicyTest, Init) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy policy;

  EXPECT_TRUE(policy.Init(history_file_path, now));

  // Creates history file
  EXPECT_TRUE(base::PathExists(history_file_path));
  int64_t file_size = -1;
  ASSERT_TRUE(base::GetFileSize(history_file_path, &file_size));
  EXPECT_EQ(file_size, 0);
}

TEST(VmmSwapUsagePolicyTest, InitTwice) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy policy;

  EXPECT_TRUE(policy.Init(history_file_path, now));
  EXPECT_FALSE(policy.Init(history_file_path, now));
}

TEST(VmmSwapUsagePolicyTest, InitIfFileNotExist) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy policy;

  ASSERT_TRUE(policy.Init(history_file_path, now));

  // The history is empty.
  EXPECT_EQ(policy.PredictDuration(now), base::TimeDelta());
  policy.OnEnabled(now - base::Days(8));
  EXPECT_EQ(policy.PredictDuration(now), base::Days(7));
}

TEST(VmmSwapUsagePolicyTest, InitIfFileExists) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy policy;

  // Create file
  base::File history_file = base::File(
      history_file_path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(history_file.IsValid());
  EXPECT_TRUE(policy.Init(history_file_path, now));

  // The history is empty.
  EXPECT_EQ(policy.PredictDuration(now), base::TimeDelta());
  policy.OnEnabled(now - base::Days(8));
  EXPECT_EQ(policy.PredictDuration(now), base::Days(7));
}

TEST(VmmSwapUsagePolicyTest, InitIfFileIsBroken) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy policy;

  base::File history_file = base::File(
      history_file_path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(history_file.IsValid());
  ASSERT_TRUE(history_file.Write(0, "invalid_data", 12));
  EXPECT_FALSE(policy.Init(history_file_path, now));

  // The history is empty.
  EXPECT_EQ(policy.PredictDuration(now), base::TimeDelta());
  policy.OnEnabled(now - base::Days(8));
  EXPECT_EQ(policy.PredictDuration(now), base::Days(7));
}

TEST(VmmSwapUsagePolicyTest, InitIfFileIsTooLong) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy policy;

  UsageHistoryEntryContainer container;
  while (container.ByteSizeLong() <= 5 * 4096) {
    auto entry = container.add_entries();
    entry->set_start_time_us(now.ToDeltaSinceWindowsEpoch().InMicroseconds());
    // 1 hour
    entry->set_duration_us(3600 * 1000 & 1000);
    entry->set_is_shutdown(false);
    now += base::Hours(1);
  }
  base::File history_file = base::File(
      history_file_path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(history_file.IsValid());
  ASSERT_TRUE(
      container.SerializeToFileDescriptor(history_file.GetPlatformFile()));

  EXPECT_FALSE(policy.Init(history_file_path, now));
  // The history is empty.
  EXPECT_EQ(policy.PredictDuration(now), base::TimeDelta());
  policy.OnEnabled(now - base::Days(8));
  EXPECT_EQ(policy.PredictDuration(now), base::Days(7));
}

TEST(VmmSwapUsagePolicyTest, OnDisabledWriteEntriesToFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));
  // 1 day
  before_policy.OnEnabled(now - base::Days(28));
  before_policy.OnDisabled(now - base::Days(27));
  // 2 days
  before_policy.OnEnabled(now - base::Days(21) - base::Hours(1));
  before_policy.OnDisabled(now - base::Days(21) - base::Minutes(30));
  before_policy.OnEnabled(now - base::Days(21) - base::Minutes(10));
  before_policy.OnDisabled(now - base::Days(19));
  // 3 days
  before_policy.OnEnabled(now - base::Days(14));
  before_policy.OnDisabled(now - base::Days(11));
  // 6 days
  before_policy.OnEnabled(now - base::Days(7));
  before_policy.OnDisabled(now - base::Days(1));
  ASSERT_EQ(before_policy.PredictDuration(now), base::Days(3));

  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_EQ(after_policy.PredictDuration(now), base::Days(3));
}

TEST(VmmSwapUsagePolicyTest, OnDestroyWriteEntriesToFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));
  // 1 days
  before_policy.OnEnabled(now - base::Days(14));
  before_policy.OnDisabled(now - base::Days(13));
  // 7 days (= 2 days enabled + 5 days shutdown)
  before_policy.OnEnabled(now - base::Days(7));
  before_policy.OnDestroy(now - base::Days(5));
  ASSERT_EQ(before_policy.PredictDuration(now), base::Days(4));

  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_EQ(after_policy.PredictDuration(now), base::Days(4));
}

TEST(VmmSwapUsagePolicyTest, OnDestroyWithoutDisable) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));
  // 14 days + 7 days
  before_policy.OnEnabled(now - base::Days(14));
  before_policy.OnDestroy(now - base::Days(1));
  ASSERT_EQ(before_policy.PredictDuration(now), base::Days(21) / 2);

  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_EQ(after_policy.PredictDuration(now), base::Days(21) / 2);
}

TEST(VmmSwapUsagePolicyTest, OnDestroyLatestEnableAfter1hour) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));
  // 1 days
  before_policy.OnEnabled(now - base::Days(14));
  before_policy.OnDisabled(now - base::Days(13));
  before_policy.OnEnabled(now - base::Days(7) - base::Hours(1));
  before_policy.OnDisabled(now - base::Days(7) - base::Minutes(30));
  // This enable record is not in the ring buffer.
  before_policy.OnEnabled(now - base::Days(7) - base::Minutes(10));
  // Write entry as if enabled 1 hour later than last enable.
  before_policy.OnDestroy(now - base::Days(1));
  ASSERT_EQ(before_policy.PredictDuration(now), base::Days(4));

  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_EQ(after_policy.PredictDuration(now), base::Days(4));
}

TEST(VmmSwapUsagePolicyTest, OnDestroyLatestEnableWithin1hour) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));
  // 1 days
  before_policy.OnEnabled(now - base::Days(14));
  before_policy.OnDisabled(now - base::Days(13));
  before_policy.OnEnabled(now - base::Days(7) - base::Hours(1));
  before_policy.OnDisabled(now - base::Days(7) - base::Minutes(30));
  // This enable record is not in the ring buffer.
  before_policy.OnEnabled(now - base::Days(7) - base::Minutes(10));
  // Write entry as if enabled 1 hour later than last enable.
  before_policy.OnDestroy(now - base::Days(7) - base::Minutes(5));
  ASSERT_EQ(before_policy.PredictDuration(now), base::Days(4));

  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_EQ(after_policy.PredictDuration(now), base::Days(4));
}

TEST(VmmSwapUsagePolicyTest, InitMultipleShutdownRecordAreIgnored) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));
  // 3 days
  before_policy.OnEnabled(now - base::Days(14));
  before_policy.OnDestroy(now - base::Days(12));
  before_policy.OnDisabled(now - base::Days(11));
  // 5 days
  before_policy.OnEnabled(now - base::Days(7));
  before_policy.OnDestroy(now - base::Days(6));
  before_policy.OnDisabled(now - base::Days(2));
  ASSERT_EQ(before_policy.PredictDuration(now), base::Days(4));

  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_EQ(after_policy.PredictDuration(now), base::Days(4));
}

TEST(VmmSwapUsagePolicyTest, OnDisabledRotateHistoryFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));

  int64_t before_file_size = -1;
  for (int i = 0; before_file_size < 5 * 4096 - 25; i++) {
    before_policy.OnEnabled(now);
    now += base::Hours(1);
    before_policy.OnDisabled(now);
    if (i >= 5 * 4096 / 25) {
      ASSERT_TRUE(base::GetFileSize(history_file_path, &before_file_size));
    }
  }
  before_policy.OnEnabled(now);
  now += base::Hours(1);
  before_policy.OnDisabled(now);
  int64_t after_file_size = -1;
  ASSERT_TRUE(base::GetFileSize(history_file_path, &after_file_size));
  EXPECT_LT(after_file_size, before_file_size);

  ASSERT_EQ(before_policy.PredictDuration(now), base::Hours(1));
  EXPECT_TRUE(after_policy.Init(history_file_path, now));
  // The file content is valid after rotation.
  EXPECT_EQ(after_policy.PredictDuration(now), base::Hours(1));
}

TEST(VmmSwapUsagePolicyTest, OnDestroyRotateHistoryFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("usage_history");
  base::Time now = base::Time::Now();
  VmmSwapUsagePolicy before_policy;
  VmmSwapUsagePolicy after_policy;
  ASSERT_TRUE(before_policy.Init(history_file_path, now));

  int64_t before_file_size = -1;
  for (int i = 0; before_file_size < 5 * 4096 - 25; i++) {
    before_policy.OnEnabled(now);
    now += base::Hours(1);
    before_policy.OnDisabled(now);
    if (i >= 5 * 4096 / 25) {
      ASSERT_TRUE(base::GetFileSize(history_file_path, &before_file_size));
    }
  }
  before_policy.OnEnabled(now);
  now += base::Hours(1);
  before_policy.OnDestroy(now);
  int64_t after_file_size = -1;
  ASSERT_TRUE(base::GetFileSize(history_file_path, &after_file_size));
  EXPECT_LT(after_file_size, before_file_size);

  ASSERT_EQ(before_policy.PredictDuration(now), base::Hours(1));
  EXPECT_TRUE(after_policy.Init(history_file_path, now));
  // The file content is valid after rotation.
  EXPECT_EQ(after_policy.PredictDuration(now), base::Hours(1));
}

TEST(VmmSwapUsagePolicyTest, MaxEntrySize) {
  UsageHistoryEntryContainer container;
  UsageHistoryEntry* new_entry = container.add_entries();
  // -1 gives the max varint length.
  new_entry->set_start_time_us(-1);
  new_entry->set_duration_us(-1);
  new_entry->set_is_shutdown(true);

  EXPECT_EQ(container.ByteSizeLong(), VmmSwapUsagePolicy::kMaxEntrySize);
}

}  // namespace vm_tools::concierge
