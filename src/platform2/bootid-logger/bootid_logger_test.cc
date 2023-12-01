// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootid-logger/bootid_logger.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <gtest/gtest.h>

class BootidLoggerTest : public ::testing::Test {};

TEST_F(BootidLoggerTest, WriteEntry) {
  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  const std::string kBootID = "12345678901234567890123456789012";

  const base::Time::Exploded exploded = {2020, 12, 1, 1, 0, 0, 0, 0};
  base::Time time;
  EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));

  EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID, time, base::Time(), 100));

  const std::string expected_entry =
      "2020-12-01T00:00:00.000000Z INFO boot_id: " + kBootID + "\n";
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}

TEST_F(BootidLoggerTest, WriteDuplicatedEntries) {
  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  const std::string kBootID = "12345678901234567890123456789012";

  {
    const base::Time::Exploded exploded = {2020, 12, 1, 1, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(
        WriteBootEntry(temporary_file, kBootID, time, base::Time(), 100));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 2, 2, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    // Should return true, since the ID is duplicated but this is not a failure.
    EXPECT_TRUE(
        WriteBootEntry(temporary_file, kBootID, time, base::Time(), 100));
  }

  const std::string expected_entry =
      "2020-12-01T00:00:00.000000Z INFO boot_id: " + kBootID + "\n";
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}

TEST_F(BootidLoggerTest, WriteMultipleEntries) {
  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  const size_t kMaxEntryNum = 3;
  const std::string kBootID1 = "12345678901234567890123456789012";
  const std::string kBootID2 = "12345678901234567890123456789013";
  const std::string kBootID3 = "12345678901234567890123456789014";
  const std::string kBootID4 = "12345678901234567890123456789015";

  {
    const base::Time::Exploded exploded = {2020, 12, 1, 1, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID1, time, base::Time(),
                               kMaxEntryNum));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 2, 2, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID2, time, base::Time(),
                               kMaxEntryNum));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 3, 3, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID3, time, base::Time(),
                               kMaxEntryNum));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 4, 4, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID4, time, base::Time(),
                               kMaxEntryNum));
  }

  const std::string expected_entry =
      "2020-12-02T00:00:00.000000Z INFO boot_id: " + kBootID2 +
      "\n"
      "2020-12-03T00:00:00.000000Z INFO boot_id: " +
      kBootID3 +
      "\n"
      "2020-12-04T00:00:00.000000Z INFO boot_id: " +
      kBootID4 + "\n";
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}

TEST_F(BootidLoggerTest, DiscardOldEntries) {
  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  const size_t kMaxEntryNum = 10;
  const std::string kBootID1 = "12345678901234567890123456789012";
  const std::string kBootID2 = "12345678901234567890123456789013";
  const std::string kBootID3 = "12345678901234567890123456789014";
  const std::string kBootID4 = "12345678901234567890123456789015";

  base::Time oldest_timestamp;
  const base::Time::Exploded exploded = {2020, 12, 1, 1, 12, 0, 0, 0};
  EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &oldest_timestamp));

  {
    const base::Time::Exploded exploded = {2020, 12, 1, 1, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID1, time, base::Time(),
                               kMaxEntryNum));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 2, 2, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID2, time, base::Time(),
                               kMaxEntryNum));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 3, 3, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID3, time, base::Time(),
                               kMaxEntryNum));
  }

  {
    const base::Time::Exploded exploded = {2020, 12, 4, 4, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID4, time, oldest_timestamp,
                               kMaxEntryNum));
  }

  const std::string expected_entry =
      "2020-12-02T00:00:00.000000Z INFO boot_id: " + kBootID2 +
      "\n"
      "2020-12-03T00:00:00.000000Z INFO boot_id: " +
      kBootID3 +
      "\n"
      "2020-12-04T00:00:00.000000Z INFO boot_id: " +
      kBootID4 + "\n";
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}

TEST_F(BootidLoggerTest, WriteCurrentBootEntry) {
  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));
  const size_t kMaxEntryNum = 1;

  WriteCurrentBootEntry(temporary_file, base::Time(), kMaxEntryNum);

  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  std::string boot_entry = std::string(base::TrimWhitespaceASCII(
      file_contents, base::TrimPositions::TRIM_TRAILING));
  EXPECT_TRUE(ValidateBootEntry(boot_entry)) << boot_entry;
  std::string boot_id = ExtractBootId(boot_entry);
  EXPECT_EQ(boot_id, GetCurrentBootId());
}

TEST_F(BootidLoggerTest, ApppendToExistingFile) {
  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  // Prepare the file with the existing entries.
  const std::string kExistingEntry1 =
      "2020-12-01T00:00:00.000000Z INFO boot_id: "
      "12345678901234567890123456789001\n";
  const std::string kExistingEntry2 =
      "2020-12-02T00:00:00.000000Z INFO boot_id: "
      "12345678901234567890123456789002\n";
  EXPECT_TRUE(
      base::WriteFile(temporary_file, kExistingEntry1 + kExistingEntry2));

  // Write an entry.
  const std::string kBootID3 = "12345678901234567890123456789003";
  {
    const base::Time::Exploded exploded = {2020, 12, 1, 3, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(
        WriteBootEntry(temporary_file, kBootID3, time, base::Time(), 100));
  }

  // Confirms that the entry is written.
  const std::string expected_entry =
      kExistingEntry1 + kExistingEntry2 +
      "2020-12-03T00:00:00.000000Z INFO boot_id: " + kBootID3 + "\n";
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}

TEST_F(BootidLoggerTest, KeepExistingEntryLocalTimezone) {
  const size_t kMaxEntryNum = 999;

  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  // Prepare the file with the existing entries.
  const std::string kExistingEntry1 =
      "2020-12-01T00:00:00.000000+00:00 INFO boot_id: "
      "12345678901234567890123456789001\n";
  const std::string kExistingEntry2 =
      "2020-12-02T00:00:00.000000+00:00 INFO boot_id: "
      "12345678901234567890123456789002\n";
  EXPECT_TRUE(
      base::WriteFile(temporary_file, kExistingEntry1 + kExistingEntry2));

  // Write an entry.
  const std::string kBootID3 = "12345678901234567890123456789003";
  {
    const base::Time::Exploded exploded = {2020, 12, 1, 3, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID3, time, base::Time(),
                               kMaxEntryNum));
  }

  // Confirms that the entry is written.
  const std::string expected_entry =
      kExistingEntry1 + kExistingEntry2 +
      "2020-12-03T00:00:00.000000Z INFO boot_id: " + kBootID3 + "\n";
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}

TEST_F(BootidLoggerTest, KeepExistingEntryLocalTimezoneDuplicated) {
  const size_t kMaxEntryNum = 999;

  base::FilePath temporary_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&temporary_file));

  // Prepare the file with the existing entries.
  const std::string kExistingEntry1 =
      "2020-12-01T00:00:00.000000Z INFO boot_id: "
      "12345678901234567890123456789001\n";
  const std::string kBootID2 = "12345678901234567890123456789002";
  const std::string kExistingEntry2 =
      "2020-12-02T00:00:00.000000Z INFO boot_id: " + kBootID2 + "\n";
  EXPECT_TRUE(
      base::WriteFile(temporary_file, kExistingEntry1 + kExistingEntry2));

  // Write an entry.
  {
    const base::Time::Exploded exploded = {2020, 12, 1, 3, 0, 0, 0, 0};
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(exploded, &time));
    // Should return true, even if the ID is duplicated.
    EXPECT_TRUE(WriteBootEntry(temporary_file, kBootID2, time, base::Time(),
                               kMaxEntryNum));
  }

  // Confirms that the entry is not written, since it is duplicated.
  const std::string expected_entry = kExistingEntry1 + kExistingEntry2;
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(temporary_file, &file_contents));
  EXPECT_EQ(expected_entry, file_contents);
}
