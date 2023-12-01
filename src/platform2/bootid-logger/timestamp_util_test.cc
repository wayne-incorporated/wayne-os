// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootid-logger/timestamp_util.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/time/time.h>
#include <gtest/gtest.h>

namespace {
base::Time TimeFromUTCExploded(base::Time::Exploded exploded) {
  base::Time time;
  EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
  return time;
}
}  // anonymous namespace

class TimestampUtilTest : public ::testing::Test {};

TEST_F(TimestampUtilTest, GetFirstTimestamp) {
  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temporary_file = temp_dir.GetPath().Append("temp.log");

  // Prepares a test log file.
  {
    std::string data_latest(
        "2020-06-21T23:17:27.000000Z test\n"
        "2020-06-22T23:17:27.000000Z test\n"
        "2020-06-23T23:17:27.000000Z test\n"
        "2020-06-24T23:17:27.000000Z test\n");
    EXPECT_TRUE(base::WriteFile(temporary_file, data_latest));
  }

  base::Time::Exploded kTestTimeExploded = {2020, 06, 0, 21, 23, 17, 27, 0};
  base::Time temporary_file_latest_time;
  EXPECT_TRUE(base::Time::FromUTCExploded(kTestTimeExploded,
                                          &temporary_file_latest_time));

  base::Time oldest_last_modified = GetFirstTimestamp(temporary_file);
  EXPECT_EQ(oldest_last_modified, temporary_file_latest_time);
}

TEST_F(TimestampUtilTest, GetOldestTimestampFromLogFiles) {
  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  std::string base_log_name("temp.log");

  // Prepares test log files in the test directory.
  {
    base::FilePath temporary_file_latest =
        temp_dir.GetPath().Append(base_log_name);
    base::FilePath temporary_file_old1 =
        temp_dir.GetPath().Append(base_log_name + ".1");
    base::FilePath temporary_file_old2 =
        temp_dir.GetPath().Append(base_log_name + ".2");

    std::string data_latest(
        "2020-06-21T22:17:27.000000Z test\n2020-06-21T23:17:27.000000Z test");
    std::string data_old1(
        "2020-06-20T22:17:27.000000Z test\n2020-06-21T23:18:27.000000Z test");
    std::string data_old2(
        "2020-06-19T22:17:27.000000Z test\n2020-06-21T23:18:27.000000Z test");
    EXPECT_TRUE(base::WriteFile(temporary_file_latest, data_latest));
    EXPECT_TRUE(base::WriteFile(temporary_file_old1, data_old1));
    EXPECT_TRUE(base::WriteFile(temporary_file_old2, data_old2));
  }

  base::Time::Exploded kTestTimeExploded = {2020, 06, 0, 19, 22, 17, 27, 0};
  base::Time temporary_file_latest_time;
  EXPECT_TRUE(base::Time::FromUTCExploded(kTestTimeExploded,
                                          &temporary_file_latest_time));

  base::Time oldest_last_modified =
      GetOldestTimestampFromLogFiles(temp_dir.GetPath(), base_log_name);

  EXPECT_EQ(oldest_last_modified, temporary_file_latest_time);
}

TEST_F(TimestampUtilTest, GetOldestModifiedTime) {
  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  const char* log_file_names[] = {"temp1.log", "temp2.log", NULL};

  std::string base_log1_name(log_file_names[0]);
  std::string base_log2_name(log_file_names[1]);

  // Prepares test log files in the test directory.
  {
    base::FilePath temporary_file_latest =
        temp_dir.GetPath().Append(base_log1_name);
    base::FilePath temporary_file_old1 =
        temp_dir.GetPath().Append(base_log1_name + ".1");
    base::FilePath temporary_file_old2 =
        temp_dir.GetPath().Append(base_log1_name + ".2");

    std::string data_latest(
        "2020-06-21T22:17:27.000000Z test\n2020-06-21T23:17:27.000000Z test");
    std::string data_old1(
        "2020-06-20T22:17:27.000000Z test\n2020-06-21T23:18:27.000000Z test");
    std::string data_old2(
        "2020-06-19T22:17:27.000000Z test\n2020-06-21T23:18:27.000000Z test");
    EXPECT_TRUE(base::WriteFile(temporary_file_latest, data_latest));
    EXPECT_TRUE(base::WriteFile(temporary_file_old1, data_old1));
    EXPECT_TRUE(base::WriteFile(temporary_file_old2, data_old2));
  }

  // Prepares test log files in the test directory.
  {
    base::FilePath temporary_file_latest =
        temp_dir.GetPath().Append(base_log2_name);
    base::FilePath temporary_file_old1 =
        temp_dir.GetPath().Append(base_log2_name + ".1");
    base::FilePath temporary_file_old2 =
        temp_dir.GetPath().Append(base_log2_name + ".2");

    std::string data_latest(
        "2020-07-21T22:17:27.000000Z test\n2020-06-21T23:17:27.000000Z test");
    std::string data_old1(
        "2020-07-20T22:17:27.000000Z test\n2020-06-21T23:18:27.000000Z test");
    std::string data_old2(
        "2020-07-19T22:17:27.000000Z test\n2020-06-21T23:18:27.000000Z test");
    EXPECT_TRUE(base::WriteFile(temporary_file_latest, data_latest));
    EXPECT_TRUE(base::WriteFile(temporary_file_old1, data_old1));
    EXPECT_TRUE(base::WriteFile(temporary_file_old2, data_old2));
  }

  base::Time::Exploded kTestTimeExploded = {2020, 06, 0, 19, 22, 17, 27, 0};
  base::Time temporary_file_latest_time;
  EXPECT_TRUE(base::Time::FromUTCExploded(kTestTimeExploded,
                                          &temporary_file_latest_time));

  base::Time oldest_last_modified =
      GetOldestModifiedTime(temp_dir.GetPath(), log_file_names);

  EXPECT_EQ(oldest_last_modified, temporary_file_latest_time);
}

TEST_F(TimestampUtilTest, ExtractTimestampString) {
  std::string example_entry1("2020-07-21T22:17:27.000000Z test");
  base::Time expected_time1 =
      TimeFromUTCExploded({2020, 07, 0, 21, 22, 17, 27, 0});
  EXPECT_EQ(expected_time1, ExtractTimestampString(example_entry1));

  std::string example_entry2("2020-07-21T22:17:27.000000+12:00 test");
  base::Time expected_time2 =
      TimeFromUTCExploded({2020, 07, 0, 21, 10, 17, 27, 0});
  EXPECT_EQ(expected_time2, ExtractTimestampString(example_entry2));

  std::string example_entry3("2020-07-21T22:17:27.000000-02:00 test");
  base::Time expected_time3 =
      TimeFromUTCExploded({2020, 07, 0, 22, 0, 17, 27, 0});
  EXPECT_EQ(expected_time3, ExtractTimestampString(example_entry3));
}
