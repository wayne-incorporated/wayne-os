// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_parser_audit.h"

#include <cmath>
#include <optional>
#include <string>
#include <utility>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "re2/re2.h"

namespace croslog {

namespace {
// Minimum length: the size of potential minimum log message.
constexpr size_t kMinimumLength = sizeof("type=X msg=Y(Z): W") - 1;

// Return the time in RFC3339 format.
std::string GetTimeString(const base::Time& timestamp) {
  // Retrieve timezone offset.
  struct tm lt = {0};
  time_t milliseconds = timestamp.ToTimeT();
  localtime_r(&milliseconds, &lt);
  int32_t timezone_offset_sec = lt.tm_gmtoff;

  base::Time::Exploded time_exploded;
  timestamp.LocalExplode(&time_exploded);
  std::string time_str = base::StringPrintf(
      "%d-%02d-%02dT%02d:%02d:%02d.%03d000%+03d:%02d", time_exploded.year,
      time_exploded.month, time_exploded.day_of_month, time_exploded.hour,
      time_exploded.minute, time_exploded.second, time_exploded.millisecond,
      (timezone_offset_sec / 3600),
      ((std::abs(timezone_offset_sec) / 60) % 60));
  return time_str;
}

constexpr LazyRE2 kLineRegexp = {
    R"(type=([^ ]+) msg=([^(]+)\(([\d\.]+):\d+\): (.+))"};

constexpr LazyRE2 kPidRegexp = {R"(\bpid=(\d+))"};

}  // namespace

LogParserAudit::LogParserAudit() = default;

MaybeLogEntry LogParserAudit::ParseInternal(std::string&& entire_line) {
  if (entire_line.empty()) {
    // Returns an invalid value if the line is invalid or empty.
    return std::nullopt;
  }

  if (entire_line.size() < kMinimumLength) {
    LOG(WARNING) << "The line is too short: invalid format?";
    return std::nullopt;
  }

  std::string type;
  std::string tag;
  std::string time_str;
  std::string message;
  if (!RE2::FullMatch(entire_line, *kLineRegexp, &type, &tag, &time_str,
                      &message)) {
    LOG(WARNING) << "Invalid line: " << entire_line;
    return std::nullopt;
  }

  double time_in_seconds;
  if (!base::StringToDouble(time_str, &time_in_seconds)) {
    LOG(WARNING) << "Invalid timestamp: " << entire_line;
    return std::nullopt;
  }

  int pid = -1;
  std::string pid_str;
  if (RE2::PartialMatch(message, *kPidRegexp, &pid_str) &&
      base::StringToInt(pid_str, &pid)) {
    pid_str = "[" + pid_str + "]";
  } else {
    pid_str = "";
    pid = -1;
  }

  base::Time time = base::Time::FromDoubleT(time_in_seconds);

  // Generate a string with the same format as syslog.
  std::string generated_entire_line = base::StringPrintf(
      "%s INFO %s%s: %s %s", GetTimeString(time).c_str(), tag.c_str(),
      pid_str.c_str(), type.c_str(), message.c_str());

  return LogEntry{time, Severity::INFO,     std::move(tag),
                  pid,  std::move(message), std::move(generated_entire_line)};
}

}  // namespace croslog
