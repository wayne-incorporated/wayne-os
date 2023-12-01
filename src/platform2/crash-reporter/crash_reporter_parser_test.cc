// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_reporter_parser.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "crash-reporter/anomaly_detector_test_utils.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Return;

using ::anomaly::CrashReport;
using ::anomaly::CrashReporterParser;
using ::anomaly::GetTestLogMessages;
using ::anomaly::ParserRun;
using ::anomaly::ParserTest;
using ::anomaly::ReplaceMsgContent;
using ::test_util::AdvancingClock;
using ::test_util::CreateFile;

namespace {

constexpr char kDefaultProcFileNr[] = "1 2 3";
constexpr char kDefaultProcMeminfo[] =
    R"(MemTotal:       196702244 kB
MemFree:        9114216 kB
MemAvailable:   172626840 kB
)";
constexpr char kDefaultMessageLog[] =
    R"(Jul 20 14:55:03 localhost systemd[1]: Starting PackageKit Daemon...
Jul 20 14:55:03 localhost dbus-daemon[1531]: [system] Successfully activated
Jul 20 14:55:03 iby3.lax.corp.google.com systemd[1]: Started PackageKit Daemon.
)";
constexpr char kOlderChromeLog[] = "Older Chrome Log\n";
constexpr char kNewerChromeLog[] = "Newer Chrome Log\n";

// Writing this out as a string instead building it up so I can see it looks
// like what I expect. As you can see, there are a few extra newlines vs the
// ideal, but it's not worth extra parsing logic in CrashReporterParser to get
// rid of them.
constexpr char kDefaultExpectedText[] =
    R"(===/proc/sys/fs/file-nr===
1 2 3
===/proc/meminfo===
MemTotal:       196702244 kB
MemFree:        9114216 kB
MemAvailable:   172626840 kB

===tail /var/log/messages===
Jul 20 14:55:03 localhost systemd[1]: Starting PackageKit Daemon...
Jul 20 14:55:03 localhost dbus-daemon[1531]: [system] Successfully activated
Jul 20 14:55:03 iby3.lax.corp.google.com systemd[1]: Started PackageKit Daemon.

===tail most recent /var/log/chrome===
Newer Chrome Log

===tail previous /var/log/chrome===
Older Chrome Log
)";

class CrashReporterParserTest : public ::testing::Test {
 public:
  // Creates a file in our fake "Chrome system logs" directory with the given
  // name and contents, and then sets its last modified time to the given
  // value.
  void CreateAndTouchChromeLog(const base::StringPiece file_name,
                               const base::StringPiece contents,
                               const base::Time::Exploded& last_modified_time) {
    const base::FilePath chrome_log_path =
        paths::Get(paths::kSystemChromeLogDirectory).Append(file_name);
    EXPECT_TRUE(CreateFile(chrome_log_path, contents));
    base::Time time;
    EXPECT_TRUE(base::Time::FromUTCExploded(last_modified_time, &time));
    EXPECT_TRUE(base::TouchFile(chrome_log_path, time, time));
  }

  // Make a parser and set it up. In particular:
  // 1. Set it to have an AdvancingClock
  // 2. Make it always capture logs.
  // 3. Set up the file system with a standard set of fake logs. The directory
  //    with the logs is in |temp_dir_|. Note that if temp_dir_ already exists,
  //    the previous temporary directory is erased and a new one created.
  std::unique_ptr<CrashReporterParser> MakeParser(
      std::unique_ptr<MetricsLibraryMock> metrics) {
    temp_dir_ = std::make_unique<base::ScopedTempDir>();
    bool made_dir = temp_dir_->CreateUniqueTempDir();
    // Can't use ASSERT_TRUE because we are in a helper function.
    EXPECT_TRUE(made_dir);
    if (made_dir) {
      const base::FilePath& temp_path = temp_dir_->GetPath();
      paths::SetPrefixForTesting(temp_path);

      EXPECT_TRUE(
          CreateFile(paths::Get(paths::kProcFileNr), kDefaultProcFileNr));
      EXPECT_TRUE(
          CreateFile(paths::Get(paths::kProcMeminfo), kDefaultProcMeminfo));
      EXPECT_TRUE(
          CreateFile(paths::Get(paths::kMessageLogPath), kDefaultMessageLog));
      // Note that we must update last modified time. Otherwise the two log
      // files can be so close in time that the 'latest' is ambiguous.
      // (Especially since base::FileEnumerator::GetInfo() rounds down to the
      // second -- this shouldn't be a problem in real life, but it's a problem
      // in this unit test.)
      const base::Time::Exploded older_time = {
          .year = 2019,
          .month = 7,
          .day_of_week = 1,
          .day_of_month = 20,
          .hour = 15,
          .minute = 29,
          .second = 15,
          .millisecond = 412,
      };
      CreateAndTouchChromeLog("chrome_20190720-150000", kOlderChromeLog,
                              older_time);

      const base::Time::Exploded newer_time = {
          .year = 2019,
          .month = 7,
          .day_of_week = 1,
          .day_of_month = 20,
          .hour = 16,
          .minute = 5,
          .second = 22,
          .millisecond = 783,
      };
      CreateAndTouchChromeLog("chrome_20190720-153000", kNewerChromeLog,
                              newer_time);
    }

    // Amount that the AdvancingClock we pass to CrashReporterParser's
    // constructor will advance on each Now() call. Less that the normal 10
    // seconds because each match calls Now() once, and the interleaved tests
    // want to get 3 matches without going past the timeout.
    const base::TimeDelta kClockAdvanceAmount = base::Seconds(1);

    EXPECT_CALL(*metrics, Init()).Times(1);
    auto parser = std::make_unique<CrashReporterParser>(
        std::make_unique<AdvancingClock>(kClockAdvanceAmount),
        std::move(metrics), true /* testonly_send_all */);
    return parser;
  }

  // Add two Chrome log files that will be more recent than the Chrome log files
  // added by MakeParser. The contents will be |current_chrome_log| for the
  // newest file and |previous_chrome_log| for the next-newest file.
  void AddMoreRecentChromeLogFiles(base::StringPiece current_chrome_log,
                                   base::StringPiece previous_chrome_log) {
    const base::Time::Exploded previous_time = {
        .year = 2019,
        .month = 7,
        .day_of_week = 1,
        .day_of_month = 21,
        .hour = 5,
        .minute = 23,
        .second = 8,
        .millisecond = 641,
    };
    CreateAndTouchChromeLog("chrome_20190721-022334", previous_chrome_log,
                            previous_time);
    const base::Time::Exploded current_time = {
        .year = 2019,
        .month = 7,
        .day_of_week = 1,
        .day_of_month = 21,
        .hour = 8,
        .minute = 55,
        .second = 7,
        .millisecond = 643,
    };
    CreateAndTouchChromeLog("chrome_20190721-060001", current_chrome_log,
                            current_time);
  }

  enum ExpectedCrashReports { kExpectNoCrashReport, kExpectOneCrashReport };

  // Call enough CrashReporterParser::PeriodicUpdate enough times that
  // AdvancingClock advances at least CrashReporterParser::kTimeout.
  void RunCrashReporterPeriodicUpdate(
      CrashReporterParser* parser,
      ExpectedCrashReports expected_crash_reports) {
    std::vector<CrashReport> crash_reports;
    // Our AdvancingClock advances 1 second per call. The "times 2" is to make
    // sure we get well past the timeout.
    const int kTimesToRun = 2 * CrashReporterParser::kTimeout.InSeconds();
    for (int count = 0; count < kTimesToRun; ++count) {
      auto result = parser->PeriodicUpdate();
      if (result) {
        crash_reports.push_back(*result);
      }
    }

    if (expected_crash_reports == kExpectNoCrashReport) {
      EXPECT_THAT(crash_reports, IsEmpty());
    } else {
      EXPECT_THAT(crash_reports,
                  ElementsAre(CrashReport(expected_text_, expected_flags_)));
    }
  }

  // Created in MakeParser().
  std::unique_ptr<base::ScopedTempDir> temp_dir_;

  // If kExpectOneCrashReport, this is the text we expect to see.
  std::string expected_text_ = kDefaultExpectedText;

  // If kExpectOneCrashReport, these are the flags we expect to see.
  // The default value matches the UID in TEST_CHROME_CRASH_MATCH.txt
  std::vector<std::string> expected_flags_ = {
      "--missed_chrome_crash", "--pid=1570",
      "--recent_miss_count=1",  // 1 because this event itself was a miss.
      "--recent_match_count=0", "--pending_miss_count=0"};
};

const ParserRun empty{.expected_size = 0};

// Apply to TEST_CHROME_CRASH_MATCH.txt to get a missed call.
const ParserRun missed_call{
    .find_this = std::string(
        "Received crash notification for chrome[1570] user 1000 (called "
        "directly)"),
    .replace_with = std::string("[user] Received crash notification for "
                                "btdispatch[2734] sig 6, user 218 "
                                "group 218"),
    .expected_size = 0};

}  // namespace

TEST_F(CrashReporterParserTest, MatchedCrashTest) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.CrashesFromKernel"))
      .WillOnce(Return(true));
  auto parser = MakeParser(std::move(metrics));
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {empty}, parser.get());

  // Calling PeriodicUpdate should not send new Cros events to UMA.
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectNoCrashReport);
}

TEST_F(CrashReporterParserTest, ReverseMatchedCrashTest) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.CrashesFromKernel"))
      .WillOnce(Return(true));
  auto parser = MakeParser(std::move(metrics));
  ParserTest("TEST_CHROME_CRASH_MATCH_REVERSED.txt", {empty}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectNoCrashReport);
}

TEST_F(CrashReporterParserTest, UnmatchedCallFromChromeTest) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA(_)).Times(0);
  auto parser = MakeParser(std::move(metrics));
  ParserRun no_kernel_call = empty;
  no_kernel_call.find_this = std::string(
      "Received crash notification for chrome[1570] sig 11, user 1000 group "
      "1000 (ignoring call by kernel - chrome crash");
  no_kernel_call.replace_with = std::string(
      "[user] Received crash notification for btdispatch[2734] sig 6, user 218 "
      "group 218");
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {no_kernel_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectNoCrashReport);
}

TEST_F(CrashReporterParserTest, UnmatchedCallFromKernelTest) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.CrashesFromKernel"))
      .WillOnce(Return(true));
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.MissedCrashes"))
      .WillOnce(Return(true));
  auto parser = MakeParser(std::move(metrics));
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

TEST_F(CrashReporterParserTest, InterleavedMessagesTest) {
  auto log_msgs = GetTestLogMessages(
      test_util::GetTestDataPath("TEST_CHROME_CRASH_MATCH_INTERLEAVED.txt",
                                 /*use_testdata=*/true));
  std::sort(log_msgs.begin(), log_msgs.end());
  do {
    auto metrics = std::make_unique<MetricsLibraryMock>();
    EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.CrashesFromKernel"))
        .Times(3)
        .WillRepeatedly(Return(true));
    auto parser = MakeParser(std::move(metrics));
    auto crash_reports = ParseLogMessages(parser.get(), log_msgs);
    EXPECT_THAT(crash_reports, IsEmpty()) << " for message set:\n"
                                          << base::JoinString(log_msgs, "\n");
    RunCrashReporterPeriodicUpdate(parser.get(), kExpectNoCrashReport);
  } while (std::next_permutation(log_msgs.begin(), log_msgs.end()));
}

TEST_F(CrashReporterParserTest, InterleavedMismatchedMessagesTest) {
  expected_flags_ = {
      "--missed_chrome_crash", "--pid=1570",
      "--recent_miss_count=1",   // 1 because this event itself was a miss.
      "--recent_match_count=2",  // The other 2 PIDs in the file.
      "--pending_miss_count=0"};
  auto log_msgs = GetTestLogMessages(
      test_util::GetTestDataPath("TEST_CHROME_CRASH_MATCH_INTERLEAVED.txt",
                                 /*use_testdata=*/true));

  ReplaceMsgContent(&log_msgs,
                    "Received crash notification for chrome[1570] user 1000 "
                    "(called directly)",
                    "Received crash notification for chrome[1571] user 1000 "
                    "(called directly)");
  std::sort(log_msgs.begin(), log_msgs.end());
  do {
    auto metrics = std::make_unique<MetricsLibraryMock>();
    EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.CrashesFromKernel"))
        .Times(3)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.MissedCrashes"))
        .WillOnce(Return(true));
    auto parser = MakeParser(std::move(metrics));
    auto crash_reports = ParseLogMessages(parser.get(), log_msgs);
    EXPECT_THAT(crash_reports, IsEmpty()) << " for message set:\n"
                                          << base::JoinString(log_msgs, "\n");
    RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
  } while (std::next_permutation(log_msgs.begin(), log_msgs.end()));
}

TEST_F(CrashReporterParserTest, PendingAndRecentMissCount) {
  auto log_msgs = GetTestLogMessages(
      test_util::GetTestDataPath("TEST_CHROME_CRASH_MATCH_INTERLEAVED.txt",
                                 /*use_testdata=*/true));

  ReplaceMsgContent(&log_msgs,
                    "Received crash notification for chrome[1570] user 1000 "
                    "(called directly)",
                    "Received crash notification for chrome[1571] user 1000 "
                    "(called directly)");
  auto metrics = std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.CrashesFromKernel"))
      .Times(5)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*metrics, SendCrosEventToUMA("Crash.Chrome.MissedCrashes"))
      .Times(3)
      .WillRepeatedly(Return(true));
  auto parser = MakeParser(std::move(metrics));
  auto crash_reports = ParseLogMessages(parser.get(), log_msgs);
  EXPECT_THAT(crash_reports, IsEmpty()) << " for message set:\n"
                                        << base::JoinString(log_msgs, "\n");

  // Run 15 periodic updates to force the clock to advance by 15 seconds.
  // 15 seconds is half of CrashReporterParser::kTimeout, so that should be
  // enough that the new pending miss won't be handled in the last
  // PeriodicUpdate, but not so much that the previous miss will be handled.
  for (int i = 0; i < CrashReporterParser::kTimeout.InSeconds() / 2; ++i) {
    EXPECT_EQ(parser->PeriodicUpdate(), std::nullopt);
  }

  // Add in one more called-for-kernel so that we have another pending miss.
  EXPECT_EQ(parser->ParseLogEntry(
                "[user] Received crash notification for chrome[777] sig 10, "
                "user 1000 group 1000 (ignoring call by kernel - chrome crash; "
                "waiting for chrome to call us directly)"),
            std::nullopt);
  // Run PeriodicUpdate until the report for the miss in the INTERLEAVED file
  // comes out. That should be PID 1570.
  expected_flags_ = {
      "--missed_chrome_crash", "--pid=1570",
      "--recent_miss_count=1",    // 1 because this event itself was a miss.
      "--recent_match_count=2",   // The other 2 PIDs in the file.
      "--pending_miss_count=1"};  // The pending miss we just added above.
  // We're not using RunCrashReporterPeriodicUpdate here because we want to stop
  // as soon as we get a CrashReport returned.
  bool got_crash_report = false;
  // kMaxTimesToRun is just a safely so we don't loop forever if PeriodicUpdate
  // is broken and never returns a CrashReport.
  const int kMaxTimesToRun = 2 * CrashReporterParser::kTimeout.InSeconds();
  for (int count = 0; !got_crash_report && count < kMaxTimesToRun; ++count) {
    auto result = parser->PeriodicUpdate();
    if (result) {
      got_crash_report = true;
      EXPECT_EQ(result, CrashReport(expected_text_, expected_flags_));
    }
  }
  EXPECT_TRUE(got_crash_report);

  // Now that we got the miss from the INTERLEAVED file, we expect the next
  // miss CrashReport to be the one we added above in the direct call to
  // ParseLogEntry. That should be PID 777.
  expected_flags_ = {"--missed_chrome_crash", "--pid=777",
                     "--recent_miss_count=2",   // The one we're returning plus
                                                // the PID 1570 one.
                     "--recent_match_count=2",  // The other 2 PIDs in the file.
                     "--pending_miss_count=0"};
  got_crash_report = false;
  for (int count = 0; !got_crash_report && count < kMaxTimesToRun; ++count) {
    auto result = parser->PeriodicUpdate();
    if (result) {
      got_crash_report = true;
      EXPECT_EQ(result, CrashReport(expected_text_, expected_flags_));
    }
  }
  EXPECT_TRUE(got_crash_report);

  // Run the PeriodicUpload long enough to clear the recent counts.
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectNoCrashReport);

  // Add in one more pending miss.
  EXPECT_EQ(parser->ParseLogEntry(
                "[user] Received crash notification for chrome[772] sig 10, "
                "user 1000 group 1000 (ignoring call by kernel - chrome crash; "
                "waiting for chrome to call us directly)"),
            std::nullopt);

  // We should get a CrashReport for the called-by-kernel line we just added
  // with a direct call to ParseLogEntry, but all those others (PID 777 and the
  // ones from the INTERLEAVED file) should have been so long ago that they are
  // not counted in the recent miss / recent match counts.
  expected_flags_ = {"--missed_chrome_crash", "--pid=772",
                     "--recent_miss_count=1", "--recent_match_count=0",
                     "--pending_miss_count=0"};
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Test what happens if we try to capture logs but they don't exist. We should
// still get a report telling us that the logs aren't found. The important thing
// is that we still get a report even if the file access gives us errors.
TEST_F(CrashReporterParserTest, CaptureFilesDontExist) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kProcFileNr)));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kProcMeminfo)));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kMessageLogPath)));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kSystemChromeLogDirectory)
                                   .Append("chrome_20190720-150000")));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kSystemChromeLogDirectory)
                                   .Append("chrome_20190720-153000")));
  expected_text_ =
      R"(===/proc/sys/fs/file-nr===
<read failed>
===/proc/meminfo===
<read failed>
===tail /var/log/messages===
Could not open
===tail most recent /var/log/chrome===
<no chrome log found>
===tail previous /var/log/chrome===
<no chrome-previous log found>)";
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Test that if we only have a single Chrome log file, we still report the
// contents of that file.
TEST_F(CrashReporterParserTest, OneChromeLog) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kSystemChromeLogDirectory)
                                   .Append("chrome_20190720-150000")));
  expected_text_ =
      R"(===/proc/sys/fs/file-nr===
1 2 3
===/proc/meminfo===
MemTotal:       196702244 kB
MemFree:        9114216 kB
MemAvailable:   172626840 kB

===tail /var/log/messages===
Jul 20 14:55:03 localhost systemd[1]: Starting PackageKit Daemon...
Jul 20 14:55:03 localhost dbus-daemon[1531]: [system] Successfully activated
Jul 20 14:55:03 iby3.lax.corp.google.com systemd[1]: Started PackageKit Daemon.

===tail most recent /var/log/chrome===
Newer Chrome Log

===tail previous /var/log/chrome===
<no chrome-previous log found>)";
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Test that if we only have a large number of Chrome log files, we report the
// contents of the two most recent. Also confirms that chrome and
// chrome.PREVIOUS symlinks are ignored.
TEST_F(CrashReporterParserTest, ManyChromeLogs) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));
  const base::Time::Exploded oldest_time = {
      .year = 2019,
      .month = 7,
      .day_of_week = 1,
      .day_of_month = 20,
      .hour = 17,
      .minute = 22,
      .second = 23,
      .millisecond = 121,
  };
  CreateAndTouchChromeLog("chrome_20190720-160300", "Ignore this one\n",
                          oldest_time);
  const base::Time::Exploded previous_time = {
      .year = 2019,
      .month = 7,
      .day_of_week = 2,
      .day_of_month = 21,
      .hour = 3,
      .minute = 45,
      .second = 1,
      .millisecond = 334,
  };
  CreateAndTouchChromeLog("chrome_20190720-235833",
                          "This is now the previous\n", previous_time);
  const base::Time::Exploded most_recent_time = {
      .year = 2019,
      .month = 7,
      .day_of_week = 2,
      .day_of_month = 21,
      .hour = 7,
      .minute = 7,
      .second = 7,
      .millisecond = 777,
  };
  CreateAndTouchChromeLog("chrome_20190721-040506", "This is the current\n",
                          most_recent_time);

  // Note that both symlinks point to the wrong file, to show that we are not
  // reading the symlinks. Since this code is checked in after 2019-07-21,
  // the symlinks should be more recent than any of the files, too (I don't
  // believe TouchFile works correctly on symlinks; it sets the time of the
  // underlying file.)
  EXPECT_TRUE(CreateSymbolicLink(
      paths::Get(paths::kSystemChromeLogDirectory)
          .Append("chrome_20190720-150000"),
      paths::Get(paths::kSystemChromeLogDirectory).Append("chrome")));
  EXPECT_TRUE(CreateSymbolicLink(
      paths::Get(paths::kSystemChromeLogDirectory)
          .Append("chrome_20190720-150000"),
      paths::Get(paths::kSystemChromeLogDirectory).Append("chrome.PREVIOUS")));

  expected_text_ =
      R"(===/proc/sys/fs/file-nr===
1 2 3
===/proc/meminfo===
MemTotal:       196702244 kB
MemFree:        9114216 kB
MemAvailable:   172626840 kB

===tail /var/log/messages===
Jul 20 14:55:03 localhost systemd[1]: Starting PackageKit Daemon...
Jul 20 14:55:03 localhost dbus-daemon[1531]: [system] Successfully activated
Jul 20 14:55:03 iby3.lax.corp.google.com systemd[1]: Started PackageKit Daemon.

===tail most recent /var/log/chrome===
This is the current

===tail previous /var/log/chrome===
This is now the previous
)";
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Test that GetLast50Lines correctly retrieves the last 50 lines from a file.
TEST_F(CrashReporterParserTest, LongLogs) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));

  // Make /var/log/messages more than 50 lines.
  std::string long_message_log;
  for (int i = 0; i < 5000; i++) {
    base::StrAppend(&long_message_log,
                    {"This is line ", base::NumberToString(i), "\n"});
  }
  EXPECT_EQ(base::WriteFile(paths::Get(paths::kMessageLogPath),
                            long_message_log.data(), long_message_log.size()),
            long_message_log.size());

  std::string expected_long_message_log_tail;
  for (int i = 4950; i < 5000; i++) {
    base::StrAppend(&expected_long_message_log_tail,
                    {"This is line ", base::NumberToString(i), "\n"});
  }

  // Make the previous chrome log exactly 50 lines.
  std::string long_previous_chrome_log;
  for (int i = 0; i < CrashReporterParser::kNumLogLinesCaptured; i++) {
    base::StrAppend(&long_previous_chrome_log,
                    {"Chrome previous line ", base::NumberToString(i), "\n"});
  }

  // Make the current chrome log 51 lines, with the 1st newline the first
  // character of the file (no read-before-beginning-of-buffer).
  std::string long_current_chrome_log = "\n";
  std::string expected_current_chrome_log_tail;
  for (int i = 0; i < CrashReporterParser::kNumLogLinesCaptured; i++) {
    base::StrAppend(&long_current_chrome_log,
                    {"Chrome current line ", base::NumberToString(i), "\n"});
    base::StrAppend(&expected_current_chrome_log_tail,
                    {"Chrome current line ", base::NumberToString(i), "\n"});
  }
  AddMoreRecentChromeLogFiles(long_current_chrome_log,
                              long_previous_chrome_log);

  expected_text_ = base::StrCat({
      R"(===/proc/sys/fs/file-nr===
1 2 3
===/proc/meminfo===
MemTotal:       196702244 kB
MemFree:        9114216 kB
MemAvailable:   172626840 kB

===tail /var/log/messages===
)",
      expected_long_message_log_tail,
      "\n===tail most recent /var/log/chrome===\n",
      expected_current_chrome_log_tail,
      "\n===tail previous /var/log/chrome===\n", long_previous_chrome_log});

  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Test that the "last 50 lines" capture works as expected if there is only a
// single gigantic line in the file.
TEST_F(CrashReporterParserTest, LongLine) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));

  std::string long_line;
  for (int i = 0; i < 10000; i++) {
    base::StrAppend(&long_line, {base::NumberToString(i), "|"});
  }
  EXPECT_EQ(base::WriteFile(paths::Get(paths::kMessageLogPath),
                            long_line.data(), long_line.size()),
            long_line.size());
  const std::string expected_message_log_tail = long_line.substr(
      long_line.length() - CrashReporterParser::kMaxLogBytesRead);

  expected_text_ = base::StrCat({
      R"(===/proc/sys/fs/file-nr===
1 2 3
===/proc/meminfo===
MemTotal:       196702244 kB
MemFree:        9114216 kB
MemAvailable:   172626840 kB

===tail /var/log/messages===
)",
      expected_message_log_tail,
      R"(
===tail most recent /var/log/chrome===
Newer Chrome Log

===tail previous /var/log/chrome===
Older Chrome Log
)"});
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Test that the "last 50 lines" capture works as expected if there are \0's in
// a log file.
TEST_F(CrashReporterParserTest, EmbeddedNuls) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));

  // Make message_log a short log with embedded nuls.
  std::string message_log;
  for (int i = 0; i < 25; i++) {
    base::StrAppend(&message_log,
                    {base::NumberToString(i), base::StringPiece("\0\n", 2)});
  }
  EXPECT_EQ(std::count(message_log.begin(), message_log.end(), '\0'), 25);
  EXPECT_EQ(base::WriteFile(paths::Get(paths::kMessageLogPath),
                            message_log.data(), message_log.size()),
            message_log.size());

  // Make the previous chrome log a long log file with embedded nuls.
  std::string long_previous_chrome_log;
  for (int i = 0; i < 500; i++) {
    base::StrAppend(&long_previous_chrome_log,
                    {"Chrome previous line ", base::NumberToString(i),
                     base::StringPiece("\0\n", 2)});
  }
  std::string expected_previous_chrome_log_tail;
  for (int i = 450; i < 500; i++) {
    base::StrAppend(&expected_previous_chrome_log_tail,
                    {"Chrome previous line ", base::NumberToString(i),
                     base::StringPiece("\0\n", 2)});
  }
  EXPECT_EQ(std::count(expected_previous_chrome_log_tail.begin(),
                       expected_previous_chrome_log_tail.end(), '\0'),
            CrashReporterParser::kNumLogLinesCaptured);

  // Make the current chrome log 51 lines with embedded nuls, with the 1st
  // newline the first/ character of the file (no
  // read-before-beginning-of-buffer).
  std::string long_current_chrome_log = "\n";
  std::string expected_current_chrome_log_tail;
  for (int i = 0; i < CrashReporterParser::kNumLogLinesCaptured; i++) {
    base::StrAppend(&long_current_chrome_log,
                    {"Chrome current line ", base::NumberToString(i),
                     base::StringPiece("\0\n", 2)});
    base::StrAppend(&expected_current_chrome_log_tail,
                    {"Chrome current line ", base::NumberToString(i),
                     base::StringPiece("\0\n", 2)});
  }
  EXPECT_EQ(std::count(expected_current_chrome_log_tail.begin(),
                       expected_current_chrome_log_tail.end(), '\0'),
            CrashReporterParser::kNumLogLinesCaptured);
  AddMoreRecentChromeLogFiles(long_current_chrome_log,
                              long_previous_chrome_log);

  // Create a meminfo with embedded nuls too.
  std::string meminfo("Mem\05", 5);
  EXPECT_EQ(base::WriteFile(paths::Get(paths::kProcMeminfo), meminfo.data(),
                            meminfo.size()),
            meminfo.size());

  expected_text_ = base::StrCat({
      R"(===/proc/sys/fs/file-nr===
1 2 3
===/proc/meminfo===
)",
      meminfo, R"(
===tail /var/log/messages===
)",
      message_log, R"(
===tail most recent /var/log/chrome===
)",
      expected_current_chrome_log_tail, R"(
===tail previous /var/log/chrome===
)",
      expected_previous_chrome_log_tail});
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}

// Prove that logs are captured when we see the miss, not when PeriodicUpdate
// runs.
TEST_F(CrashReporterParserTest, LogsAreCapturedAtMissTime) {
  auto metrics = std::make_unique<MetricsLibraryMock>();
  auto parser = MakeParser(std::move(metrics));
  ParserTest("TEST_CHROME_CRASH_MATCH.txt", {missed_call}, parser.get());

  EXPECT_TRUE(base::AppendToFile(paths::Get(paths::kProcFileNr), "more"));
  EXPECT_TRUE(base::AppendToFile(paths::Get(paths::kProcMeminfo), "more"));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kMessageLogPath)));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kSystemChromeLogDirectory)
                                   .Append("chrome_20190720-150000")));
  EXPECT_TRUE(base::DeleteFile(paths::Get(paths::kSystemChromeLogDirectory)
                                   .Append("chrome_20190720-153000")));
  RunCrashReporterPeriodicUpdate(parser.get(), kExpectOneCrashReport);
}
