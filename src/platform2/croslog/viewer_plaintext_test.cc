// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/viewer_plaintext.h"

#include <gtest/gtest.h>

#include "croslog/cursor_util.h"
#include "croslog/test_util.h"

namespace croslog {

class ViewerPlaintextTest : public ::testing::Test {
 public:
  ViewerPlaintextTest() = default;
  ViewerPlaintextTest(const ViewerPlaintextTest&) = delete;
  ViewerPlaintextTest& operator=(const ViewerPlaintextTest&) = delete;

  static std::vector<BootRecords::BootEntry> GenerateBootLog(base::Time now) {
    std::vector<BootRecords::BootEntry> boot_entries;
    boot_entries.emplace_back(now + base::Seconds(0),
                              "46640bbceeb149a696171d1ea34516ad");
    boot_entries.emplace_back(now + base::Seconds(2),
                              "9fa644cb05dc4e3ebe3be322ac8d1e86");
    return boot_entries;
  }

  static LogEntry GenerateLogEntry(base::Time time) {
    return LogEntry{time, Severity::ERROR, "TAG",
                    1234, "MESSAGE",       "ENTIRE STRING"};
  }
};

TEST_F(ViewerPlaintextTest, ShouldFilterOutEntry) {
  {
    Config c;
    LogEntry e{base::Time::Now(), Severity::ERROR, "TAG", 1234,
               "MESSAGE",         "ENTIRE STRING"};

    ViewerPlaintext v(c);
    EXPECT_FALSE(v.ShouldFilterOutEntry(e));
  }

  {
    Config c;
    c.identifier = "TAG1";
    LogEntry e1{base::Time::Now(), Severity::ERROR, "TAG1", 1234,
                "MESSAGE",         "ENTIRE STRING"};
    LogEntry e2{base::Time::Now(), Severity::ERROR, "TAG2", 1234,
                "MESSAGE",         "ENTIRE STRING"};

    ViewerPlaintext v(c);
    EXPECT_FALSE(v.ShouldFilterOutEntry(e1));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e2));
  }

  {
    Config c;
    c.severity = Severity::ERROR;
    LogEntry e1{base::Time::Now(), Severity::WARNING, "TAG", 1234,
                "MESSAGE",         "ENTIRE STRING"};
    LogEntry e2{base::Time::Now(), Severity::ERROR, "TAG", 1234,
                "MESSAGE",         "ENTIRE STRING"};
    LogEntry e3{base::Time::Now(), Severity::CRIT, "TAG", 1234,
                "MESSAGE",         "ENTIRE STRING"};

    ViewerPlaintext v(c);
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }

  {
    Config c;
    c.grep = "M.....E";
    LogEntry e1{base::Time::Now(), Severity::ERROR, "TAG", 1234,
                "MESSAGE",         "ENTIRE STRING"};
    LogEntry e2{base::Time::Now(), Severity::ERROR, "TAG", 1234,
                "xxMESSAGE",       "ENTIRE STRING"};
    LogEntry e3{base::Time::Now(), Severity::ERROR, "TAG", 1234,
                "MESSAGExx",       "ENTIRE STRING"};
    LogEntry e4{base::Time::Now(), Severity::ERROR, "TAG", 1234,
                "xxMESSAGExx",     "ENTIRE STRING"};
    LogEntry e5{base::Time::Now(), Severity::ERROR, "TAG", 1234,
                "message",         "ENTIRE STRING"};

    ViewerPlaintext v(c);
    EXPECT_FALSE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e4));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e5));
  }
}

TEST_F(ViewerPlaintextTest, ShouldFilterOutEntryWithSinceAndUntil) {
  {
    Config c;
    c.since = TimeFromExploded(2020, 12, 10, 11, 12, 13);

    LogEntry e1 = GenerateLogEntry(c.since - base::Seconds(2));
    LogEntry e2 = GenerateLogEntry(c.since + base::Seconds(0));
    LogEntry e3 = GenerateLogEntry(c.since + base::Seconds(2));

    ViewerPlaintext v(c);
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }

  {
    Config c;
    c.until = TimeFromExploded(2020, 12, 10, 11, 12, 13);

    LogEntry e1 = GenerateLogEntry(c.until - base::Seconds(2));
    LogEntry e2 = GenerateLogEntry(c.until + base::Seconds(0));
    LogEntry e3 = GenerateLogEntry(c.until + base::Seconds(2));

    ViewerPlaintext v(c);
    EXPECT_FALSE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e3));
  }
}

TEST_F(ViewerPlaintextTest, ShouldFilterOutEntryWithBootId) {
  base::Time now = base::Time::Now();

  // First boot.
  {
    Config c;
    c.boot = "46640bbceeb149a696171d1ea34516ad";

    LogEntry e1 = GenerateLogEntry(now - base::Seconds(2));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e3 = GenerateLogEntry(now + base::Seconds(2));

    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e3));
  }

  // Second (last) boot.
  {
    Config c;
    c.boot = "9fa644cb05dc4e3ebe3be322ac8d1e86";

    LogEntry e1 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(2));
    LogEntry e3 = GenerateLogEntry(now + base::Seconds(4));

    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }

  // Last (second) boot.
  {
    Config c;
    c.boot = "";

    LogEntry e1 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(2));
    LogEntry e3 = GenerateLogEntry(now + base::Seconds(4));

    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }

  // Last (second) boot.
  {
    Config c;
    c.boot = "0";

    LogEntry e1 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(2));
    LogEntry e3 = GenerateLogEntry(now + base::Seconds(4));

    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }

  // Invalid boot.
  {
    Config c;
    c.boot = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    LogEntry e1 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(2));

    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e2));
  }
}

TEST_F(ViewerPlaintextTest, ShouldFilterOutEntryWithCursor) {
  base::Time now = base::Time::Now();

  {
    Config c;
    c.cursor = GenerateCursor(now);

    LogEntry e1 = GenerateLogEntry(now - base::Seconds(2));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e3 = GenerateLogEntry(now + base::Seconds(2));

    ViewerPlaintext v(c);
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }

  {
    Config c;
    c.after_cursor = GenerateCursor(now);

    LogEntry e1 = GenerateLogEntry(now - base::Seconds(2));
    LogEntry e2 = GenerateLogEntry(now + base::Seconds(0));
    LogEntry e3 = GenerateLogEntry(now + base::Seconds(2));

    ViewerPlaintext v(c);
    EXPECT_TRUE(v.ShouldFilterOutEntry(e1));
    EXPECT_TRUE(v.ShouldFilterOutEntry(e2));
    EXPECT_FALSE(v.ShouldFilterOutEntry(e3));
  }
}

TEST_F(ViewerPlaintextTest, GetBootIdAt) {
  base::Time now = base::Time::Now();

  {
    Config c;
    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));

    // Found no corresponding boot (before the 1st boot).
    EXPECT_TRUE(v.GetBootIdAt(now - base::Seconds(100)).empty());

    // Found the 1st boot.
    EXPECT_EQ("46640bbceeb149a696171d1ea34516ad", v.GetBootIdAt(now));
    EXPECT_EQ("46640bbceeb149a696171d1ea34516ad",
              v.GetBootIdAt(now + base::Seconds(1)));

    // Found the 2nd (current) boot.
    EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86",
              v.GetBootIdAt(now + base::Seconds(2)));
    EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86",
              v.GetBootIdAt(now + base::Seconds(3)));
    EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86",
              v.GetBootIdAt(now + base::Seconds(100)));
  }

  {
    Config c;
    ViewerPlaintext v(c, BootRecords(GenerateBootLog(now)));

    // Found the 2nd (current) boot.
    EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86",
              v.GetBootIdAt(now + base::Seconds(100)));
    EXPECT_EQ("9fa644cb05dc4e3ebe3be322ac8d1e86",
              v.GetBootIdAt(now + base::Seconds(2)));

    // Found the 1st boot.
    EXPECT_EQ("46640bbceeb149a696171d1ea34516ad",
              v.GetBootIdAt(now + base::Seconds(1)));
    EXPECT_EQ("46640bbceeb149a696171d1ea34516ad", v.GetBootIdAt(now));

    // Found no corresponding boot (before the 1st boot).
    EXPECT_TRUE(v.GetBootIdAt(now - base::Seconds(100)).empty());
  }
}

}  // namespace croslog
