// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_reporter_parser.h"

#include <optional>
#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/strcat.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace {

// Erase all entries in times that are older than too_old.
void EraseTimesBefore(base::Time too_old, std::vector<base::Time>* times) {
  auto it = times->begin();
  // Assume the times are in order. This is not *strictly* true, because
  // clock->Now() will in some cases return values out of order (e.g. if the
  // system clock is adjusted), but we won't break anything (no crash, no
  // undefined behavior) if that happens, we'll just get a slightly-incorrect
  // count. So take the optimization savings of assuming the times are in order.
  while (it != times->end() && *it < too_old) {
    ++it;
  }
  times->erase(times->begin(), it);
}

}  // namespace

namespace anomaly {

constexpr LazyRE2 chrome_crash_called_directly = {
    "Received crash notification for chrome\\[(\\d+)\\][[:alnum:] ]+"
    "\\(called directly\\)"};

constexpr LazyRE2 chrome_crash_called_by_kernel = {
    "Received crash notification for chrome\\[(\\d+)\\][[:alnum:], ]+"
    "\\(ignoring call by kernel - chrome crash"};

constexpr char kUMACrashesFromKernel[] = "Crash.Chrome.CrashesFromKernel";
constexpr char kUMAMissedCrashes[] = "Crash.Chrome.MissedCrashes";
constexpr base::TimeDelta CrashReporterParser::kTimeout;
constexpr base::TimeDelta CrashReporterParser::kTimeoutForRecentUsage;
constexpr int CrashReporterParser::kNumLogLinesCaptured;
constexpr int CrashReporterParser::kMaxLogBytesRead;

CrashReporterParser::CrashReporterParser(
    std::unique_ptr<base::Clock> clock,
    std::unique_ptr<MetricsLibraryInterface> metrics_lib,
    bool testonly_send_all)
    : clock_(std::move(clock)),
      metrics_lib_(std::move(metrics_lib)),
      always_capture_logs_for_test_(testonly_send_all) {
  metrics_lib_->Init();
}

CrashReport CrashReporterParser::MakeCrashReport(const UnmatchedCrash& crash) {
  // Note that we don't have a good signature -- we don't have any way to
  // really distinguish one missed crash from another -- so the text is just the
  // log we want to send.
  int recent_miss_count =
      static_cast<int>(recent_unmatched_crash_times_.size());
  int recent_match_count = static_cast<int>(recent_matched_crash_times_.size());
  // Count pending missing. collector=CHROME will never turn into a miss, so
  // don't count those.
  int pending_miss_count = 0;
  for (const UnmatchedCrash& unmatched : unmatched_crashes_) {
    if (unmatched.collector == Collector::USER) {
      ++pending_miss_count;
    }
  }
  // -1 so we don't count the current missed crash as both pending and recent.
  --pending_miss_count;
  return CrashReport(
      base::StrCat({"===/proc/sys/fs/file-nr===\n", crash.file_nr,
                    "\n===/proc/meminfo===\n", crash.meminfo,
                    "\n===tail /var/log/messages===\n", crash.last_50_messages,
                    "\n===tail most recent /var/log/chrome===\n",
                    crash.last_50_chrome_current,
                    "\n===tail previous /var/log/chrome===\n",
                    crash.last_50_chrome_previous}),
      {"--missed_chrome_crash", base::StringPrintf("--pid=%d", crash.pid),
       base::StringPrintf("--recent_miss_count=%d", recent_miss_count),
       base::StringPrintf("--recent_match_count=%d", recent_match_count),
       base::StringPrintf("--pending_miss_count=%d", pending_miss_count)});
}

// static
std::string CrashReporterParser::GetLast50Lines(
    const base::FilePath& file_path) {
  base::File file(file_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    LOG(WARNING) << "Could not open " << file_path.value();
    return "Could not open";
  }

  char buffer[kMaxLogBytesRead];
  int64_t length = file.GetLength();
  if (length < 0) {
    LOG(WARNING) << "Error getting length of " << file_path.value();
    return "Error getting length\n";
  }

  int read;
  if (length > kMaxLogBytesRead) {
    read = file.Read(length - kMaxLogBytesRead, buffer, kMaxLogBytesRead);
  } else {
    read = file.Read(0, buffer, kMaxLogBytesRead);
  }

  if (read < 0) {
    LOG(WARNING) << "Error reading " << file_path.value();
    return "Error during read\n";
  }

  if (read == 0) {
    return "<empty>\n";
  }

  int newlines = 0;
  int pos = read - 1;
  for (; pos >= 0; --pos) {
    if (buffer[pos] == '\n') {
      ++newlines;
      // Find the \n that is just before the 50th line.
      if (newlines > kNumLogLinesCaptured) {
        break;
      }
    }
  }
  // pos is either -1 or on the \n before the 50th line. Either way, we're
  // 1 before where we want to be.
  ++pos;
  return std::string(buffer + pos, read - pos);
}

// static
void CrashReporterParser::GetChromeLogs(UnmatchedCrash* crash) {
  const base::FilePath system_log_directory =
      paths::Get(paths::kSystemChromeLogDirectory);
  // Find the two most recent Chrome logs rather than relying on the chrome &
  // chrome.PREVIOUS symlinks. Since Chrome may be crashing and restarting, we
  // risk races around the symlinks being created (for instance, if chrome gets
  // moved to chrome.PREVIOUS while are reading it, we might up reading the
  // same file twice).
  base::FileEnumerator file_enumerator(system_log_directory,
                                       false /*recursive */,
                                       base::FileEnumerator::FILES, "chrome_*");
  base::FileEnumerator::FileInfo most_recent;
  base::FileEnumerator::FileInfo next_most_recent;
  while (!file_enumerator.Next().empty()) {
    auto info = file_enumerator.GetInfo();
    if (info.GetLastModifiedTime() > most_recent.GetLastModifiedTime()) {
      next_most_recent = std::move(most_recent);
      most_recent = std::move(info);
    } else if (info.GetLastModifiedTime() >
               next_most_recent.GetLastModifiedTime()) {
      next_most_recent = std::move(info);
    }
  }

  if (!most_recent.GetName().empty()) {
    crash->last_50_chrome_current =
        GetLast50Lines(system_log_directory.Append(most_recent.GetName()));
  } else {
    crash->last_50_chrome_current = "<no chrome log found>";
  }
  if (!next_most_recent.GetName().empty()) {
    crash->last_50_chrome_previous =
        GetLast50Lines(system_log_directory.Append(next_most_recent.GetName()));
  } else {
    crash->last_50_chrome_previous = "<no chrome-previous log found>";
  }

  // We'd like to capture the most recent user Chrome logs here as well. (The
  // /home/chronos/u-*/log/chrome_* logs). However, this runs into a lot of
  // privacy issues. There can be 30-40 second delay between the time we gather
  // the logs and the time we write the crash report. During this time, the
  // user may have logged out, which means we're writing the crash report
  // outside of the user's cryptohome. We can't write user logs to locations
  // outside of their cryptohome. Solving this involves recording the location
  // we got the user logs from, passing that to crash_reporter, and then doing
  // various text manipulations to strip the user logs out if we're writing to
  // a location not inside that cryptohome. It's possible but it's complex and
  // messy and embeds some assumptions about the exact directory format being
  // used by the cryptohome system. For now we're skipping the complexity and
  // hoping the /var/log/chrome logs will have enough info to diagnose the
  // problem. (Crashpad always writes to /var/log/chrome even when someone is
  // logged in, so there's a good chance the info we want will be there.)
  //
  // Note -- if you want to change this, you also need to update the call to
  // GetCreatedCrashDirectoryByEuid in MissedCrashCollector::Collect to use a
  // different UID.
}

// static
void CrashReporterParser::CaptureLogs(UnmatchedCrash* crash) {
  crash->logs_captured = true;
  if (!base::ReadFileToString(paths::Get(paths::kProcFileNr),
                              &crash->file_nr)) {
    crash->file_nr = "<read failed>";
    // Keep going in the face of errors. One theory as to why we see missed
    // crashes is that we are resource exhausted (in particular, file-descriptor
    // exhausted). If we give up because of errors, and the file-descriptor
    // exhaustion makes it hard to read the proc files, then we won't see
    // information telling us about the file-descriptor exhaustion.
  }

  if (!base::ReadFileToString(paths::Get(paths::kProcMeminfo),
                              &crash->meminfo)) {
    crash->meminfo = "<read failed>";
  }

  crash->last_50_messages = GetLast50Lines(paths::Get(paths::kMessageLogPath));
  GetChromeLogs(crash);

  // TODO(b/160903152): We should also run /bin/ps and attach its output to
  // the logs. This would let us check that crashpad_handler is still running.
  // Similarly, we should capture the last 50 lines from dmesg, since failed fd
  // allocations are logged there.
}

bool CrashReporterParser::ShouldCaptureLogs(const UnmatchedCrash& crash) {
  if (crash.collector != Collector::USER) {
    return false;
  }

  if (always_capture_logs_for_test_) {
    return true;
  }

  // Capture logs 1-in-1000. 413 is an arbitrary number chosen to celebrate an
  // important date.
  return base::RandGenerator(1000) == 413;
}

MaybeCrashReport CrashReporterParser::ParseLogEntry(const std::string& line) {
  int pid = 0;
  UnmatchedCrash crash;
  if (RE2::PartialMatch(line, *chrome_crash_called_directly, &pid)) {
    crash.pid = pid;
    crash.collector = Collector::CHROME;
    crash.timestamp = clock_->Now();
  } else if (RE2::PartialMatch(line, *chrome_crash_called_by_kernel, &pid)) {
    crash.pid = pid;
    crash.collector = Collector::USER;
    crash.timestamp = clock_->Now();
  } else {
    return std::nullopt;
  }

  // Find the matching entry in our unmatched_crashes_ vector. We expect each
  // real chrome crash to reported twice, with the same PID -- once with "called
  // directly" and once with "ignoring call by kernel".
  for (auto it = unmatched_crashes_.begin(); it != unmatched_crashes_.end();
       ++it) {
    if (it->pid == crash.pid && it->collector != crash.collector) {
      // Found the corresponding message from the other collector. Throw away
      // both.
      unmatched_crashes_.erase(it);
      // One of the two was a crash from kernel, so record that we got a crash
      // from kernel. (We only send the events when we match or don't match;
      // this avoids having our data polluted by events just before a shutdown.)
      if (!metrics_lib_->SendCrosEventToUMA(kUMACrashesFromKernel)) {
        LOG(WARNING) << "Could not mark Chrome crash as correctly processed";
      }
      recent_matched_crash_times_.push_back(clock_->Now());
      return std::nullopt;
    }
  }

  if (ShouldCaptureLogs(crash)) {
    CaptureLogs(&crash);
  }

  unmatched_crashes_.push_back(crash);
  return std::nullopt;
}

MaybeCrashReport CrashReporterParser::PeriodicUpdate() {
  base::Time now = clock_->Now();
  base::Time too_old_for_recent_usage = now - kTimeoutForRecentUsage;
  // Remove the record of recent reports first, so that any missed crash reports
  // have the proper nearby misses & hits count.
  EraseTimesBefore(too_old_for_recent_usage, &recent_unmatched_crash_times_);
  EraseTimesBefore(too_old_for_recent_usage, &recent_matched_crash_times_);

  base::Time too_old = now - kTimeout;
  auto it = unmatched_crashes_.begin();
  MaybeCrashReport return_value;
  while (it != unmatched_crashes_.end()) {
    if (it->timestamp < too_old) {
      if (it->collector == Collector::USER) {
        if (!metrics_lib_->SendCrosEventToUMA(kUMACrashesFromKernel) ||
            !metrics_lib_->SendCrosEventToUMA(kUMAMissedCrashes)) {
          LOG(WARNING) << "Could not mark Chrome crash as missed";
        }
        recent_unmatched_crash_times_.push_back(it->timestamp);
      }
      if (it->logs_captured) {
        // In principle, we could have two log captures at about the same
        // moment and this will lose one of these. (If we have two missed
        // crashes within 10 seconds of each other.) In practice, this should
        // happen rarely enough that it won't distort our overall numbers and
        // the two log captures will have pretty much the same info anyways.
        return_value = MakeCrashReport(*it);
      }
      it = unmatched_crashes_.erase(it);
    } else {
      ++it;
    }
  }

  return return_value;
}

}  // namespace anomaly
