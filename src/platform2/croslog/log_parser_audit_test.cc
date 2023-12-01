// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_parser_audit.h"

#include <memory>
#include <string>
#include <utility>

#include "base/files/file_path.h"
#include "gtest/gtest.h"

#include "croslog/log_line_reader.h"
#include "croslog/test_util.h"

namespace croslog {

namespace {
constexpr char kTimezoneEnvName[] = "TZ";
}

class LogParserAuditTest : public ::testing::Test {
 public:
  LogParserAuditTest() = default;
  LogParserAuditTest(const LogParserAuditTest&) = delete;
  LogParserAuditTest& operator=(const LogParserAuditTest&) = delete;

  static void SetTimeZone(const char* time_zone) {
    // tzset() distinguishes between the TZ variable being present and empty
    // and not being present, so we have to consider the case of time_zone
    // being NULL.
    if (time_zone) {
      setenv(kTimezoneEnvName, time_zone, 1);
    } else {
      unsetenv(kTimezoneEnvName);
    }
    tzset();
  }

 private:
  const char* saved_tz_ = nullptr;

  void SetUp() override {
    saved_tz_ =
        getenv(kTimezoneEnvName) ? strdup(getenv(kTimezoneEnvName)) : nullptr;

    // Set up UTC as the default timezone in this test.
    SetTimeZone("UTC+00");
  }

  void TearDown() override {
    SetTimeZone(saved_tz_);
    free(const_cast<char*>(saved_tz_));
    saved_tz_ = nullptr;
  }
};

TEST_F(LogParserAuditTest, Parse) {
  LogParserAudit parser;
  LogLineReader reader(LogLineReader::Backend::FILE);
  reader.OpenFile(base::FilePath("./testdata/TEST_AUDIT_LOG"));

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-01-18T23:17:27.098000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 1, 18, 23, 17, 27, 98000), e->time());
    EXPECT_EQ(0, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ("INFO audit[0]: SECCOMP pid=0 auid=4294967296 uid=1000 gid=1000",
              s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T23:15:49.018000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 15, 49, 18000), e->time());
    EXPECT_EQ(476, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ(
        "INFO audit[476]: DAEMON_START op=start ver=2.8.4 format=raw "
        "kernel=4.4.221-17496-g92f60640939f auid=4294967295 pid=476 uid=0 "
        "ses=4294967295 subj=u:r:cros_auditd:s0 res=success",
        s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T23:15:50.925000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 15, 50, 925000), e->time());
    EXPECT_EQ(655360, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ(
        "INFO audit[655360]: AVC avc:  denied  { search } for  pid=655360 "
        "comm=\"bootstat\" name=\"dm-0\" dev=\"sysfs\" ino=17352 "
        "scontext=u:r:cros_bootstat:s0 tcontext=u:object_r:sysfs_dm:s0 "
        "tclass=dir permissive=0",
        s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T23:17:27.098000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 17, 27, 98000), e->time());
    EXPECT_EQ("test", e->tag());
    EXPECT_EQ(4844, e->pid());

    EXPECT_EQ(
        "INFO test[4844]: SECCOMP auid=4294967295 uid=1000 gid=1000 "
        "ses=4294967295 subj=u:r:cros_browser:s0 ppid=4843 pid=4844 "
        "comm=\"nacl_helper\" exe=\"/opt/google/chrome/nacl_helper\" "
        "sig=0 arch=c000003e syscall=273 compat=0 ip=0x7b7aefb1949d "
        "code=0x50000",
        s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T23:17:27.098000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 17, 27, 98000), e->time());
    EXPECT_EQ(4845, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ(
        "INFO audit[4845]: SECCOMP auid=4294967296 uid=1000 gid=1000 "
        "ses=4294967296 subj=u:r:cros_browser:s0 pid=4845 ppid=4844 "
        "comm=\"nacl_helper\" exe=\"/opt/google/chrome/nacl_helper\" "
        "sig=0 arch=c000003e syscall=273 compat=0 ip=0x7b7aefb1949d "
        "code=0x50000",
        s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T23:17:30.000000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 17, 30, 00000), e->time());
    EXPECT_EQ(-1, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ(
        "INFO audit: SECCOMP auid=4294967296 uid=1000 gid=1000 "
        "ses=4294967296 subj=u:r:cros_browser:s0 comm=\"nacl_helper\" "
        "exe=\"/opt/google/chrome/nacl_helper\" sig=0 arch=c000003e "
        "syscall=273 compat=0 ip=0x7b7aefb1949d code=0x50000",
        s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2019-09-16T14:21:41.984000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2019, 9, 16, 14, 21, 41, 984000), e->time());
    EXPECT_EQ(493, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ(
        "INFO audit[493]: DAEMON_START op=start ver=2.8.4 format=raw "
        "kernel=3.18.0-19732-gf84df209b0a1 auid=4294967295 pid=493 uid=0 "
        "ses=4294967295 subj=u:r:cros_auditd:s0 res=success",
        s.substr(33, s.size()));
  }

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS, result);
  }
}

TEST_F(LogParserAuditTest, ParseWithTimezone) {
  LogLineReader reader(LogLineReader::Backend::FILE);
  reader.OpenFile(base::FilePath("./testdata/TEST_AUDIT_LOG"));

  // MEZ (UTC+01, during non-DST)
  SetTimeZone("Europe/Berlin");
  {
    LogParserAudit parser;
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    // Compare times in UTC
    EXPECT_EQ(TimeFromExploded(2020, 1, 18, 23, 17, 27, 98000), e->time());

    // Compare time strings in the local timezone
    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-01-19T00:17:27.098000+01:00", s.substr(0, 32));
  }

  // JST (UTC+09)
  SetTimeZone("Asia/Tokyo");
  {
    LogParserAudit parser;
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    // Compare times in UTC
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 15, 49, 18000), e->time());

    // Compare time strings in the local timezone
    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-22T08:15:49.018000+09:00", s.substr(0, 32));
  }

  // PDT (UTC-07)
  SetTimeZone("America/Los_Angeles");
  {
    LogParserAudit parser;
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    // Compare times in UTC
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 15, 50, 925000), e->time());

    // Compare time strings in the local timezone
    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T16:15:50.925000-07:00", s.substr(0, 32));
  }

  // MESZ (UTC+02, during DST)
  SetTimeZone("Europe/Berlin");
  {
    LogParserAudit parser;
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    // Compare times in UTC
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 17, 27, 98000), e->time());

    // Compare time strings in the local timezone
    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-22T01:17:27.098000+02:00", s.substr(0, 32));
  }

  // UTC
  SetTimeZone("UTC+00");
  {
    LogParserAudit parser;
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    // Compare times in UTC
    EXPECT_EQ(TimeFromExploded(2020, 6, 21, 23, 17, 27, 98000), e->time());

    // Compare time strings in the local timezone
    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-06-21T23:17:27.098000+00:00", s.substr(0, 32));
  }
}

TEST_F(LogParserAuditTest, ParseLeadingNull) {
  LogParserAudit parser;
  LogLineReader reader(LogLineReader::Backend::FILE);
  reader.OpenFile(base::FilePath("./testdata/TEST_AUDIT_LOG_LEADING_NULL"));

  {
    auto [line, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    MaybeLogEntry e = parser.Parse(std::move(line));
    EXPECT_TRUE(e.has_value());

    const std::string& s = e->entire_line();
    EXPECT_EQ("2020-01-18T23:17:27.098000+00:00", s.substr(0, 32));
    EXPECT_EQ(TimeFromExploded(2020, 1, 18, 23, 17, 27, 98000), e->time());
    EXPECT_EQ(0, e->pid());
    EXPECT_EQ("audit", e->tag());

    EXPECT_EQ("INFO audit[0]: SECCOMP pid=0 auid=4294967296 uid=1000 gid=1000",
              s.substr(33, s.size()));
  }
}

}  // namespace croslog
