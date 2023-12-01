// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_parser_syslog.h"

#include <memory>
#include <string>
#include <utility>

#include "base/files/file_path.h"
#include "gtest/gtest.h"

#include "croslog/log_line_reader.h"
#include "croslog/test_util.h"

namespace croslog {

class LogParserSyslogTest : public ::testing::Test {
 public:
  LogParserSyslogTest() = default;
  LogParserSyslogTest(const LogParserSyslogTest&) = delete;
  LogParserSyslogTest& operator=(const LogParserSyslogTest&) = delete;
};

TEST_F(LogParserSyslogTest, Parse) {
  LogParserSyslog parser;

  {
    std::string line =
        "2020-05-25T14:15:22.402258+09:00 ERROR tag[0123]: MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("ERROR", s.substr(33, 5));
    EXPECT_EQ(Severity::ERROR, e->severity());

    EXPECT_EQ("tag", e->tag());
    EXPECT_EQ(123, e->pid());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }

  {
    std::string line = "2020-05-25T14:15:22.402258Z ERROR tag[0123]: MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 27);

    EXPECT_EQ("ERROR", s.substr(28, 5));
    EXPECT_EQ(Severity::ERROR, e->severity());

    EXPECT_EQ("tag", e->tag());
    EXPECT_EQ(123, e->pid());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258Z", s.substr(0, 27));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, 0), e->time());
  }

  {
    std::string line = "2020-05-25T14:15:22.402258+09:00 INFO kernel: MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ(Severity::INFO, e->severity());

    EXPECT_EQ("kernel", e->tag());
    EXPECT_EQ(-1, e->pid());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }
}

TEST_F(LogParserSyslogTest, ParseFromFile) {
  LogParserSyslog parser;
  LogLineReader reader(LogLineReader::Backend::FILE);
  reader.OpenFile(base::FilePath("./testdata/TEST_NORMAL_LOG1"));
  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("INFO", s.substr(33, 4));
    EXPECT_EQ(Severity::INFO, e->severity());

    EXPECT_EQ("sshd[5963]", s.substr(38, 10));
    EXPECT_EQ("sshd", e->tag());
    EXPECT_EQ(5963, e->pid());

    EXPECT_EQ("Accepted", s.substr(50, 8));
    EXPECT_EQ("Accepted", e->message().substr(0, 8));

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("INFO", s.substr(33, 4));
    EXPECT_EQ(Severity::INFO, e->severity());

    EXPECT_EQ("sshd[5965]", s.substr(38, 10));
    EXPECT_EQ("sshd", e->tag());
    EXPECT_EQ(5965, e->pid());

    EXPECT_EQ("Accepted", s.substr(50, 8));
    EXPECT_EQ("Accepted", e->message().substr(0, 8));

    EXPECT_EQ("2020-05-25T14:15:22.402260+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402260, +9), e->time());
  }
}

TEST_F(LogParserSyslogTest, ParseInvalid) {
  LogParserSyslog parser;

  {
    // Without semicollon.
    std::string maybe_line =
        "2020-05-25T14:15:22.402258+09:00 ERROR tag[0123] MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(maybe_line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("ERROR", s.substr(33, 5));
    EXPECT_EQ(Severity::ERROR, e->severity());

    EXPECT_EQ("tag", e->tag());
    EXPECT_EQ(123, e->pid());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }

  {
    // Without semicollon and pid.
    std::string maybe_line =
        "2020-05-25T14:15:22.402258+09:00 ERROR tag MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(maybe_line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("ERROR", s.substr(33, 5));
    EXPECT_EQ(Severity::ERROR, e->severity());

    EXPECT_EQ("tag", e->tag());
    EXPECT_EQ(-1, e->pid());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }

  {
    // Without tag.
    std::string maybe_line = "2020-05-25T14:15:22.402258+09:00 ERROR MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(maybe_line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("ERROR", s.substr(33, 5));
    EXPECT_EQ(Severity::ERROR, e->severity());

    EXPECT_TRUE(e->tag().empty());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }

  {
    // Without tag and priority.
    std::string maybe_line = "2020-05-25T14:15:22.402258+09:00 MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(maybe_line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ(Severity::UNSPECIFIED, e->severity());
    EXPECT_TRUE(e->tag().empty());
    EXPECT_EQ("MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }

  {
    // Only UTC time present.
    std::string maybe_line = "2020-05-25T14:15:22.402258Z";
    EXPECT_FALSE(parser.Parse(std::move(maybe_line)).has_value());
  }

  {
    // Only time with time zone present.
    std::string maybe_line = "2020-05-25T14:15:22.402258+09:00";
    EXPECT_FALSE(parser.Parse(std::move(maybe_line)).has_value());
  }

  {
    // Only incomplete time present: missing suffix 'Z' for UTC.
    std::string maybe_line = "2020-05-25T14:15:22.402258";
    EXPECT_FALSE(parser.Parse(std::move(maybe_line)).has_value());
  }

  {
    // Incomplete time present with log: missing suffix 'Z' for UTC.
    std::string maybe_line =
        "2020-05-25T14:15:22.402258 ERROR tag[0123]: MESSAGE";
    EXPECT_FALSE(parser.Parse(std::move(maybe_line)).has_value());
  }

  {
    // Only incomplete time with time zone present: incomplete tz offset.
    std::string maybe_line = "2020-05-25T14:15:22.402258+09:0";
    EXPECT_FALSE(parser.Parse(std::move(maybe_line)).has_value());
  }

  {
    // Incomplete time with time zone with log.
    std::string maybe_line =
        "2020-05-25T14:15:22.402258+09:0 ERROR tag[0123]: MESSAGE";
    EXPECT_FALSE(parser.Parse(std::move(maybe_line)).has_value());
  }

  {
    // Unended pid part.
    std::string maybe_line =
        "2020-05-25T14:15:22.402258+09:00 ERROR tag[0123 MESSAGE";

    MaybeLogEntry e = parser.Parse(std::move(maybe_line));
    EXPECT_TRUE(e.has_value());
    const std::string& s = e->entire_line();
    EXPECT_GT(s.size(), 32);

    EXPECT_EQ("ERROR", s.substr(33, 5));
    EXPECT_EQ(Severity::ERROR, e->severity());

    EXPECT_EQ("tag", e->tag());
    EXPECT_EQ(-1, e->pid());
    EXPECT_EQ("[0123 MESSAGE", e->message());

    EXPECT_EQ("2020-05-25T14:15:22.402258+09:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 5, 25, 14, 15, 22, 402258, +9), e->time());
  }
}

}  // namespace croslog
