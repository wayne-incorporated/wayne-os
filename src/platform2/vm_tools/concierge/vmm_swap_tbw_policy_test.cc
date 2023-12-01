// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vmm_swap_tbw_policy.h"

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/time/time.h>
#include <gtest/gtest.h>

namespace vm_tools::concierge {

TEST(VmmSwapTbwPolicyTest, CanSwapOut) {
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  EXPECT_TRUE(policy.CanSwapOut());
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutWithin1dayTarget) {
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  policy.Record(399);

  EXPECT_TRUE(policy.CanSwapOut());
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutExceeds1dayTarget) {
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  policy.Record(400);

  EXPECT_FALSE(policy.CanSwapOut());
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutExceeds1dayTargetWithMultiRecords) {
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  // Buffer size is 28 but they are merged within 1 day.
  for (int i = 0; i < 100; i++) {
    policy.Record(4);
  }

  EXPECT_FALSE(policy.CanSwapOut());
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutAfterExceeds1dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  policy.Record(400, now - base::Days(1));

  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutExceeds7dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 7; i++) {
    policy.Record(200, now - base::Days(6 - i));
  }

  EXPECT_FALSE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutNotExceeds7dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 6; i++) {
    policy.Record(200, now - base::Days(6 - i));
  }
  policy.Record(199, now);

  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutAfterExceeds7dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 7; i++) {
    policy.Record(200, now - base::Days(7 - i));
  }

  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutExceeds28dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 28; i++) {
    policy.Record(100, now - base::Days(27 - i));
  }

  EXPECT_FALSE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutNotExceeds28dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 27; i++) {
    policy.Record(100, now - base::Days(27 - i));
  }
  policy.Record(99, now);

  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutAfterExceeds28dayTarget) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 28; i++) {
    policy.Record(100, now - base::Days(28 - i));
  }

  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, CanSwapOutIgnoreRotatedObsoleteData) {
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  for (int i = 0; i < 28; i++) {
    policy.Record(400, now - base::Days(56 - i));
  }
  policy.Record(399, now);

  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, Init) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  EXPECT_TRUE(policy.Init(history_file_path, now));

  // Creates history file
  EXPECT_TRUE(base::PathExists(history_file_path));
}

TEST(VmmSwapTbwPolicyTest, InitTwice) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  EXPECT_TRUE(policy.Init(history_file_path, now));
  EXPECT_FALSE(policy.Init(history_file_path, now));
}

TEST(VmmSwapTbwPolicyTest, InitIfFileNotExist) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  EXPECT_TRUE(policy.Init(history_file_path, now));

  // By default it is not allowed to swap out for 1 day.
  EXPECT_FALSE(policy.CanSwapOut(now + base::Days(1) - base::Seconds(1)));
  EXPECT_TRUE(policy.CanSwapOut(now + base::Days(1)));
}

TEST(VmmSwapTbwPolicyTest, InitIfFileExists) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  // Create file
  base::File history_file =
      base::File(history_file_path, base::File::Flags::FLAG_CREATE |
                                        base::File::Flags::FLAG_WRITE);
  ASSERT_TRUE(history_file.IsValid());
  EXPECT_TRUE(policy.Init(history_file_path, now));

  // The history is empty.
  EXPECT_TRUE(policy.CanSwapOut(now));
}

TEST(VmmSwapTbwPolicyTest, InitIfFileIsBroken) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy policy;
  policy.SetTargetTbwPerDay(100);

  base::File history_file =
      base::File(history_file_path, base::File::Flags::FLAG_CREATE |
                                        base::File::Flags::FLAG_WRITE);
  ASSERT_TRUE(history_file.IsValid());
  ASSERT_TRUE(history_file.Write(0, "invalid_data", 12));
  EXPECT_FALSE(policy.Init(history_file_path, now));

  // The pessimistic history does not allow to swap out for 1 day.
  EXPECT_FALSE(policy.CanSwapOut(now + base::Days(1) - base::Seconds(1)));
  EXPECT_TRUE(policy.CanSwapOut(now + base::Days(1)));
}

TEST(VmmSwapTbwPolicyTest, InititialHistoryFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy before_policy;
  VmmSwapTbwPolicy after_policy;
  before_policy.SetTargetTbwPerDay(100);
  after_policy.SetTargetTbwPerDay(100);

  EXPECT_TRUE(before_policy.Init(history_file_path, now));
  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  // The initialized history from policy1 is written into the history file.
  EXPECT_FALSE(after_policy.CanSwapOut(now + base::Days(1) - base::Seconds(1)));
  EXPECT_TRUE(after_policy.CanSwapOut(now + base::Days(1)));
}

TEST(VmmSwapTbwPolicyTest, RecordWriteEntriesToFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy before_policy;
  VmmSwapTbwPolicy after_policy;
  before_policy.SetTargetTbwPerDay(100);
  after_policy.SetTargetTbwPerDay(100);
  // Create empty file
  base::File history_file =
      base::File(history_file_path, base::File::Flags::FLAG_CREATE |
                                        base::File::Flags::FLAG_WRITE);
  EXPECT_TRUE(before_policy.Init(history_file_path, now));

  for (int i = 0; i < 7; i++) {
    before_policy.Record(200, now + base::Days(i));
  }
  now = now + base::Days(6);
  EXPECT_TRUE(after_policy.Init(history_file_path, now));

  EXPECT_FALSE(after_policy.CanSwapOut(now + base::Days(1) - base::Seconds(1)));
  EXPECT_TRUE(after_policy.CanSwapOut(now + base::Days(1)));
}

TEST(VmmSwapTbwPolicyTest, RecordRecompileFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath history_file_path = temp_dir.GetPath().Append("tbw_history");
  base::Time now = base::Time::Now();
  VmmSwapTbwPolicy before_policy;
  VmmSwapTbwPolicy after_policy;
  int target = 60 * 24;
  before_policy.SetTargetTbwPerDay(target);
  after_policy.SetTargetTbwPerDay(target);
  // Create empty file
  base::File history_file =
      base::File(history_file_path, base::File::Flags::FLAG_CREATE |
                                        base::File::Flags::FLAG_WRITE);
  EXPECT_TRUE(before_policy.Init(history_file_path, now));

  // minutes of 7days
  int minutes_7days = 60 * 24 * 7;
  for (int i = 0; i < minutes_7days; i++) {
    before_policy.Record(2, now + base::Minutes(i));
  }
  now = now + base::Minutes(minutes_7days - 1);
  EXPECT_FALSE(before_policy.CanSwapOut(now));
  EXPECT_TRUE(before_policy.CanSwapOut(now + base::Days(1)));
  EXPECT_TRUE(after_policy.Init(history_file_path, now));
  EXPECT_FALSE(after_policy.CanSwapOut(now));
  EXPECT_TRUE(after_policy.CanSwapOut(now + base::Days(1)));

  // Less than page size.
  EXPECT_LE(history_file.GetLength(), 4096);
}

}  // namespace vm_tools::concierge
