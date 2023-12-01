// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CRASH_REPORTER_PARSER_H_
#define CRASH_REPORTER_CRASH_REPORTER_PARSER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/time/clock.h>
#include <base/time/time.h>
#include <metrics/metrics_library.h>

#include "crash-reporter/anomaly_detector.h"

namespace anomaly {

// Anomaly_detector's collector for syslog entries from our own crash_reporter.
// Unlike other anomaly_detector collectors, this doesn't usually create
// crash reports -- ParseLogEntry always returns nullopt. Instead, it primarily
// produces UMA metrics that track how well Chrome's crash handlers (breakpad or
// crashpad) are working. If Chrome gets a segfault or such, its internal crash
// handler should invoke crash_reporter directly. Once the internal crash
// handler is done, the kernel should also invoke crash_reporter via the normal
// core pattern file. Both of these produce distinct log entries. By matching
// these up, we can detect how often the internal crash handler is failing to
// invoke crash_reporter. In particular, if we see an invoked-by-kernel message
// without a corresponding invoking-directly message, Chrome's crash handler
// failed. We record the number of unmatched invoked-by-kernel messages, and,
// for a denominator, we record the total number of invoked-by-kernel messages.
//
// (There are some cases -- "dump without crashing" -- in which Chrome will
// invoke crash_reporter but will not actually crash, and so will not produce
// an invoked-by-kernel message. This is why we go to the trouble of actually
// matching up messages from the log, instead of just counting the number of
// invoked-directly and invoked-from-kernel events. The "dump without crashing"
// events will overcount the number of successes and hide the true number of
// failures. Therefore, we ignore "dump without crashing" crashes by not
// counting the number of invoked-by-Chrome messages we see, and not reporting
// the number of unmatched invoked-by-Chrome messages.)
class CrashReporterParser : public Parser {
 public:
  // We hold on to unmatched messages for at least this long before reporting
  // them as unmatched.
  static constexpr base::TimeDelta kTimeout = base::Seconds(30);
  // We hold on to records of the # of matched and unmatched messages for this
  // long before discarding this. This is longer than kTimeout because we want
  // to know the number of crashes the crash system was trying to handle all
  // around the missed crash, not just after it,
  static constexpr base::TimeDelta kTimeoutForRecentUsage = base::Seconds(60);

  // Constants around log capture. Exposed here just for unit testing.
  // Number of lines of the various logs captured.
  static constexpr int kNumLogLinesCaptured = 50;
  // We only captures this much from the end of the file. This is usually
  // enough to get 50 lines of text. It's possible that if some lines are
  // humongous, we'll get less than 50 lines, but that's very rare and if it
  // happens, we don't lose much -- 50 lines is a bit arbitrary anyways.
  static constexpr int kMaxLogBytesRead = kNumLogLinesCaptured * 400;

  explicit CrashReporterParser(
      std::unique_ptr<base::Clock> clock,
      std::unique_ptr<MetricsLibraryInterface> metrics_lib,
      bool testonly_send_all);
  MaybeCrashReport ParseLogEntry(const std::string& line) override;
  MaybeCrashReport PeriodicUpdate() override;

 private:
  enum class Collector {
    // Log entry was from ChromeCollector.
    CHROME,

    // Log entry was from UserCollector.
    USER
  };

  struct UnmatchedCrash {
    int pid;
    base::Time timestamp;
    Collector collector;

    // Log captures. We are seeing some boards with a high crash miss rate
    // (that is, crash_reporter isn't getting called for many Chrome crashes.)
    // To investigate further, we want to grab some logs when we get a Chrome
    // crash miss. We can't do this in the normal way (in
    // CrashCollector::GetLogContents) because we don't know this is a miss for
    // 30 seconds, and we want to grab the logs at the time of the miss. So we
    // grab the logs when we first see the UserCollector log entry, and then
    // only use if PeriodicUpdate marks this a missed collection. To avoid
    // generating too many crash uploads, we also do this one of 1000 times.
    // So these fields are only filled in 1-in-1000 times and only if
    // collector == USER.

    // If false, the entries below this were not filled in.
    bool logs_captured = false;

    // Contents of /proc/sys/fs/file-nr, which lists the # of allocated file
    // handles, the number of allocated-but-unused handles, and the maximum
    // number of file handles.
    std::string file_nr;

    // Contents of /proc/meminfo.
    std::string meminfo;

    // Last 50 lines of /var/log/messages.
    std::string last_50_messages;

    // Last 50 lines of most recent /var/log/chrome_* log.
    std::string last_50_chrome_current;
    // Last 50 lines of second most recent /var/log/chrome_* log.
    std::string last_50_chrome_previous;
  };

  // Returns the last 50 lines of the file. (Or the entire file, if less than
  // 50 lines.) Not in util.cc because this function is a bit opinionated on
  // handling error messages and how important it is to get 50 lines in all
  // possible scenarios. (Specifically -- it's willing to get less than 50 lines
  // in some cases to avoid complexity, and it returns a string indicating the
  // error in place of the file contents if there is an error reading the file.)
  static std::string GetLast50Lines(const base::FilePath& file_path);

  // Take an UnmatchedCrash that has |logs_captured| of true, and turn it into
  // a CrashReport that anomaly_detector_main.cc can send to crash_reporter.
  CrashReport MakeCrashReport(const UnmatchedCrash& crash);

  // Capture the ChromeLogs in |crash|.
  static void GetChromeLogs(UnmatchedCrash* crash);

  // Capture logs (such as |last_50_messages|) in |crash|.
  static void CaptureLogs(UnmatchedCrash* crash);

  // Returns true if we should capture logs for this crash report. Outside of
  // tests, we only capture logs for .1% of Collector::USER unmatched crashes.
  bool ShouldCaptureLogs(const UnmatchedCrash& crash);

  std::unique_ptr<base::Clock> clock_;
  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
  std::vector<UnmatchedCrash> unmatched_crashes_;
  std::vector<base::Time> recent_unmatched_crash_times_;
  std::vector<base::Time> recent_matched_crash_times_;
  const bool always_capture_logs_for_test_;
};

}  // namespace anomaly

#endif  // CRASH_REPORTER_CRASH_REPORTER_PARSER_H_
