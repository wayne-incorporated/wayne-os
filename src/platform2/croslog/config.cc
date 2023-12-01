// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/config.h"

#include <memory>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/flag_helper.h>

#include "croslog/relative_time_util.h"

namespace croslog {

bool Config::ParseCommandLineArgs(int argc, const char* const argv[]) {
  DEFINE_string(source, "plaintext", "Source of logs to read.");
  DEFINE_string(output, "short", "Controls type of format to show logs.");
  DEFINE_string(lines, "all", "Limit the maximum number of lines to show.");
  DEFINE_string(boot, "", "Show logs only from specified boot.");
  DEFINE_string(identifier, "", "Show logs only for the specified identifier.");
  DEFINE_string(priority, "all",
                "Show logs only for the specified priority or more important.");
  DEFINE_string(grep, "", "Show logs only matched with the specified regexp.");
  DEFINE_string(cursor, "", "Show logs starting from the specified cursor.");
  DEFINE_bool(quiet, false, "Suppress informational messages.");
  DEFINE_bool(follow, false, "Show continiously new logs as they are written.");
  DEFINE_string(
      since, "",
      "Show entries not older than the specified date in YYYY-MM-DD "
      "or YYYYMMDD in UTC (eg. '2021-01-02'). Relative times (in seconds) may "
      "be specified, prefixed with \"-\" or \"+\", referring to times before "
      "or after the current time, respectively.");
  DEFINE_string(
      until, "",
      "Show entries not newer than the specified date in YYYY-MM-DD "
      "or YYYYMMDD in UTC (eg. '2021-01-02'). Relative times (in seconds) may "
      "be specified, prefixed with \"-\" or \"+\", referring to times before "
      "or after the current time, respectively.");

  // "after-cursor" flag manual definition (the macro doesn't support a name
  // with hyphen)
  std::string FLAG_after_cursor;
  static const char kAfterCursorHelp[] =
      "Show logs starting after the specified cursor.";
  brillo::FlagHelper::GetInstance()->AddFlag(
      std::unique_ptr<brillo::Flag>(new brillo::StringFlag(
          "after-cursor", &FLAG_after_cursor, "", kAfterCursorHelp, true)));

  // "show-cursor" flag manual definition (the macro doesn't support a name with
  // hyphen)
  bool FLAGS_show_cursor = true;
  bool FLAGS_show_nocursor = false;
  static const char kShowCursorHelp[] =
      "Show the current cursor log logs at last.";
  brillo::FlagHelper::GetInstance()->AddFlag(
      std::unique_ptr<brillo::Flag>(new brillo::BoolFlag(
          "show-cursor", &FLAGS_show_cursor, &FLAGS_show_nocursor, "true",
          kShowCursorHelp, true)));
  brillo::FlagHelper::GetInstance()->AddFlag(
      std::unique_ptr<brillo::Flag>(new brillo::BoolFlag(
          "no-show-cursor", &FLAGS_show_nocursor, &FLAGS_show_cursor, "true",
          kShowCursorHelp, false)));

  // "pager" and "no-pager" flags manual definition (the macro doesn't support a
  // name with hyphen)
  bool FLAGS_pager = false;
  bool FLAGS_no_pager = true;
  static const char kPagerHelp[] =
      "Pipe the outout into pager (not implemented yet).";
  brillo::FlagHelper::GetInstance()->AddFlag(
      std::unique_ptr<brillo::Flag>(new brillo::BoolFlag(
          "pager", &FLAGS_pager, &FLAGS_no_pager, "false", kPagerHelp, true)));
  brillo::FlagHelper::GetInstance()->AddFlag(std::unique_ptr<brillo::Flag>(
      new brillo::BoolFlag("no-pager", &FLAGS_no_pager, &FLAGS_pager, "false",
                           kPagerHelp, false)));

  brillo::FlagHelper::Init(
      argc, argv,
      "Captures the stdout/stderr of the specified program and forward them "
      "to syslog.");

  const base::CommandLine* const command_line =
      base::CommandLine::ForCurrentProcess();

  bool result = true;

  if (FLAGS_source == "journal") {
    source = SourceMode::JOURNAL_LOG;
  } else if (FLAGS_source == "plaintext") {
    source = SourceMode::PLAINTEXT_LOG;
  } else {
    LOG(ERROR) << "Specified '--source' argument is invalid. "
               << "It must be 'journal' or 'plaintext'.";
    result = false;
  }

  if (base::CompareCaseInsensitiveASCII(FLAGS_output, "short") == 0) {
    output = OutputMode::SHORT;
  } else if (base::CompareCaseInsensitiveASCII(FLAGS_output, "export") == 0) {
    output = OutputMode::EXPORT;
  } else if (base::CompareCaseInsensitiveASCII(FLAGS_output, "json") == 0) {
    output = OutputMode::JSON;
  } else {
    LOG(ERROR) << "Specified '--output' argument is invalid. "
               << "It must be 'short', 'export' or 'json'.";
    result = false;
  }

  since = base::Time();
  if (!FLAGS_since.empty()) {
    if (!base::Time::FromUTCString(FLAGS_since.c_str(), &since) &&
        !ParseRelativeTime(FLAGS_since, &since)) {
      LOG(ERROR) << "Failed to parse '--since' date.";
      result = false;
    }
  }

  until = base::Time();
  if (!FLAGS_until.empty()) {
    if (!base::Time::FromUTCString(FLAGS_until.c_str(), &until) &&
        !ParseRelativeTime(FLAGS_until, &until)) {
      LOG(ERROR) << "Failed to parse '--until' date.";
      result = false;
    }
  }

  if (FLAGS_lines.empty()) {
    // Default value when the argument is specified without a value.
    lines = 10;
  } else if (base::ToLowerASCII(FLAGS_lines) == "all") {
    // Doesn't limit (same as the default behavior without the argument).
    lines = -1;
  } else if (base::StringToInt(FLAGS_lines, &lines)) {
    if (lines < 0) {
      LOG(ERROR) << "--lines argument value must be positive.";
      result = false;
    }
  } else {
    LOG(ERROR) << "--lines argument must be a number.";
    result = false;
  }

  // "--boot" distinguishes an empty argument and undefined.
  if (command_line->HasSwitch("boot")) {
    boot = FLAGS_boot;
  }

  identifier = FLAGS_identifier;

  if (FLAGS_priority.empty() || base::ToLowerASCII(FLAGS_priority) == "all") {
    severity = Severity::UNSPECIFIED;
  } else {
    // Supports only single priority, but doesn't support range.
    const std::string& severity_str =
        command_line->GetSwitchValueASCII("priority");
    severity = SeverityFromString(severity_str);
  }

  grep = FLAGS_grep;
  cursor = FLAGS_cursor;
  after_cursor = FLAG_after_cursor;
  show_cursor = FLAGS_show_cursor;
  quiet = FLAGS_quiet;
  no_pager = FLAGS_no_pager;
  follow = FLAGS_follow;

  return result;
}

}  // namespace croslog
