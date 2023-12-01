// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/multiplexer.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "croslog/log_entry_reader.h"
#include "croslog/log_parser_syslog.h"

namespace croslog {

class LogEntryReaderTest : public ::testing::Test {
 public:
  LogEntryReaderTest() = default;
  LogEntryReaderTest(const LogEntryReaderTest&) = delete;
  LogEntryReaderTest& operator=(const LogEntryReaderTest&) = delete;
};

TEST_F(LogEntryReaderTest, GetNextEntry) {
  LogEntryReader reader(base::FilePath("./testdata/TEST_MULTILINE_LOG"),
                        std::make_unique<LogParserSyslog>(), false);

  {
    MaybeLogEntry e = reader.GetNextEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(1, e->pid());
    EXPECT_EQ("aaa\nbbb\nccc", e->message());
  }

  {
    MaybeLogEntry e = reader.GetNextEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(2, e->pid());
    EXPECT_EQ("aaa\n\nccc\n", e->message());
  }

  {
    MaybeLogEntry e = reader.GetNextEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(3, e->pid());
    EXPECT_EQ("\nbbb\nccc", e->message());
  }

  EXPECT_FALSE(reader.GetNextEntry().has_value());
}

TEST_F(LogEntryReaderTest, GetPreviousEntry) {
  LogEntryReader reader(base::FilePath("./testdata/TEST_MULTILINE_LOG"),
                        std::make_unique<LogParserSyslog>(), false);
  reader.SetPositionLast();

  {
    MaybeLogEntry e = reader.GetPreviousEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(3, e->pid());
    EXPECT_EQ("\nbbb\nccc", e->message());
  }

  {
    MaybeLogEntry e = reader.GetPreviousEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(2, e->pid());
    EXPECT_EQ("aaa\n\nccc\n", e->message());
  }

  {
    MaybeLogEntry e = reader.GetPreviousEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(1, e->pid());
    EXPECT_EQ("aaa\nbbb\nccc", e->message());
  }

  EXPECT_FALSE(reader.GetPreviousEntry().has_value());
}

TEST_F(LogEntryReaderTest, InterleaveGetNextEntryAndGetPreviousEntry) {
  LogEntryReader reader(base::FilePath("./testdata/TEST_MULTILINE_LOG"),
                        std::make_unique<LogParserSyslog>(), false);
  reader.SetPositionLast();

  {
    MaybeLogEntry e = reader.GetPreviousEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(3, e->pid());
  }

  {
    MaybeLogEntry e = reader.GetNextEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(3, e->pid());
  }

  EXPECT_FALSE(reader.GetNextEntry().has_value());

  {
    MaybeLogEntry e = reader.GetPreviousEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(3, e->pid());
  }

  {
    MaybeLogEntry e = reader.GetNextEntry();
    EXPECT_TRUE(e.has_value());
    EXPECT_EQ(3, e->pid());
  }

  EXPECT_FALSE(reader.GetNextEntry().has_value());
}

}  // namespace croslog
