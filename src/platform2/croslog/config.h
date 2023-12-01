// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_CONFIG_H_
#define CROSLOG_CONFIG_H_

#include <optional>
#include <string>

#include <base/command_line.h>
#include <base/time/time.h>

#include "croslog/severity.h"

namespace croslog {

enum class SourceMode { JOURNAL_LOG, PLAINTEXT_LOG };
enum class OutputMode { SHORT, EXPORT, JSON };

struct Config {
  bool ParseCommandLineArgs(int argc, const char* const argv[]);

  // Source of logs: see |SourceMode| enum class.
  SourceMode source = SourceMode::PLAINTEXT_LOG;
  // Formatting of logs which are shown.
  OutputMode output = OutputMode::SHORT;
  // Number to limit the lines of logs shown
  int lines = -1;
  // Boot ID to show messages only from the specific boot.
  std::optional<std::string> boot;
  // String to show message for the specified syslog identifier
  // (SYSLOG_IDENTIFIER).
  std::string identifier;
  // Severity value to filter output by message priorities or priority ranges.
  Severity severity = Severity::UNSPECIFIED;
  // Regexp string to filter output to entries where the MESSAGE= field matches
  // with.
  std::string grep;
  // Log cursor string to start showing entries from the specified location.
  std::string cursor;
  // Log cursor string to start showing entries after the specified location.
  std::string after_cursor;
  // Flag to show the cursor after the last entry.
  bool show_cursor = false;
  // Flag to suppress all informational messages.
  bool quiet = false;
  // Flag not to pipe output into a pager program.
  bool no_pager = false;
  // Flag to print a help text instead of logs.
  bool show_help = false;
  // Flag to follow appended contents.
  bool follow = false;
  // Time to show entries not older than (in UTC).
  base::Time since;
  // Time to show entries not newer than (in UTC).
  base::Time until;
};

}  // namespace croslog

#endif  // CROSLOG_CONFIG_H_
