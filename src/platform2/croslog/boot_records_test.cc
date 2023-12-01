// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/boot_records.h"

#include <memory>
#include <string>
#include <utility>

#include "base/files/file_path.h"
#include "gtest/gtest.h"

#include "croslog/log_line_reader.h"
#include "croslog/test_util.h"

namespace croslog {

class BootRecordsTest : public ::testing::Test {
 public:
  BootRecordsTest() = default;
  BootRecordsTest(const BootRecordsTest&) = delete;
  BootRecordsTest& operator=(const BootRecordsTest&) = delete;
};

TEST_F(BootRecordsTest, Load) {
  std::vector<BootRecords::BootEntry> set_entries;
  set_entries.emplace_back(TimeFromExploded(2020, 7, 1, 16, 1, 17),
                           "46640bbceeb149a696171d1ea34516ad");
  set_entries.emplace_back(TimeFromExploded(2020, 7, 3, 2, 35, 0),
                           "9fa644cb05dc4e3ebe3be322ac8d1e86");
  set_entries.emplace_back(TimeFromExploded(2020, 7, 3, 7, 23, 24),
                           "59f7d9025ea044568318171a9b4d375e");
  BootRecords boot_records(std::move(set_entries));
  const auto& entries = boot_records.boot_ranges();

  EXPECT_EQ(3, entries.size());

  EXPECT_EQ("46640bbceeb149a696171d1ea34516ad", entries[0].boot_id());
  EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86", entries[1].boot_id());
  EXPECT_EQ("59f7d9025ea044568318171a9b4d375e", entries[2].boot_id());

  EXPECT_EQ(TimeFromExploded(2020, 7, 1, 16, 1, 17), entries[0].boot_time());
  EXPECT_EQ(TimeFromExploded(2020, 7, 3, 2, 35, 0), entries[1].boot_time());
  EXPECT_EQ(TimeFromExploded(2020, 7, 3, 7, 23, 24), entries[2].boot_time());
}

TEST_F(BootRecordsTest, GetBootRange) {
  std::vector<BootRecords::BootEntry> set_entries;
  set_entries.emplace_back(TimeFromExploded(2020, 7, 3, 2, 35, 0),
                           "9fa644cb05dc4e3ebe3be322ac8d1e86");
  set_entries.emplace_back(TimeFromExploded(2020, 7, 3, 7, 23, 24),
                           "59f7d9025ea044568318171a9b4d375e");
  BootRecords boot_records(std::move(set_entries));

  const auto kFirstBootRange =
      BootRecords::BootRange(TimeFromExploded(2020, 7, 3, 2, 35, 0),
                             TimeFromExploded(2020, 7, 3, 7, 23, 24),
                             "9fa644cb05dc4e3ebe3be322ac8d1e86");
  const auto kSecondBootRange = BootRecords::BootRange(
      TimeFromExploded(2020, 7, 3, 7, 23, 24), base::Time::Max(),
      "59f7d9025ea044568318171a9b4d375e");

  // Absolute boot ids:
  EXPECT_EQ(
      kFirstBootRange,
      boot_records.GetBootRange("9fa644cb05dc4e3ebe3be322ac8d1e86").value());
  EXPECT_EQ(
      kSecondBootRange,
      boot_records.GetBootRange("59f7d9025ea044568318171a9b4d375e").value());
  EXPECT_FALSE(boot_records.GetBootRange("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                   .has_value());
  EXPECT_FALSE(boot_records.GetBootRange("59F7D9025EA044568318171A9B4D375E")
                   .has_value());

  // Relative boot offset (zero or negative):
  EXPECT_EQ(kFirstBootRange, boot_records.GetBootRange("-1").value());
  EXPECT_EQ(kSecondBootRange, boot_records.GetBootRange("-0").value());
  EXPECT_EQ(kSecondBootRange, boot_records.GetBootRange("0").value());
  EXPECT_EQ(kSecondBootRange, boot_records.GetBootRange("+0").value());

  // Relative boot offset (positive):
  EXPECT_FALSE(boot_records.GetBootRange("1").has_value());
  EXPECT_FALSE(boot_records.GetBootRange("+1").has_value());

  // Empty:
  EXPECT_EQ(kSecondBootRange, boot_records.GetBootRange("").value());

  EXPECT_FALSE(boot_records.GetBootRange("-2").has_value());

  // Invalid:
  EXPECT_FALSE(boot_records.GetBootRange("INVALID-BOOTID").has_value());
}

TEST_F(BootRecordsTest, LoadFromFile) {
  base::FilePath file_path("./testdata/TEST_BOOT_ID_LOG");

  BootRecords boot_records(file_path);
  const auto& entries = boot_records.boot_ranges();

  EXPECT_EQ(3, entries.size());

  EXPECT_EQ("46640bbceeb149a696171d1ea34516ad", entries[0].boot_id());
  EXPECT_EQ(TimeFromExploded(2020, 7, 1, 16, 1, 17), entries[0].boot_time());

  EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86", entries[1].boot_id());
  EXPECT_EQ(TimeFromExploded(2020, 7, 3, 2, 35, 0), entries[1].boot_time());

  EXPECT_EQ("59f7d9025ea044568318171a9b4d375e", entries[2].boot_id());
  EXPECT_EQ(TimeFromExploded(2020, 7, 3, 7, 23, 24), entries[2].boot_time());
}

TEST_F(BootRecordsTest, LoadFromInvalidFile) {
  base::FilePath file_path("./testdata/TEST_BOOT_ID_LOG_INVALID");

  BootRecords boot_records(file_path);
  const auto& entries = boot_records.boot_ranges();

  EXPECT_EQ(3, entries.size());

  EXPECT_EQ("46640bbceeb149a696171d1ea34516ad", entries[0].boot_id());
  EXPECT_EQ(TimeFromExploded(2020, 7, 1, 16, 1, 17), entries[0].boot_time());

  EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86", entries[1].boot_id());
  EXPECT_EQ(TimeFromExploded(2020, 7, 3, 2, 35, 0), entries[1].boot_time());

  // The invalid entry should be skipped.

  EXPECT_EQ("59f7d9025ea044568318171a9b4d375e", entries[2].boot_id());
  EXPECT_EQ(TimeFromExploded(2020, 7, 3, 7, 23, 24), entries[2].boot_time());
}

}  // namespace croslog
