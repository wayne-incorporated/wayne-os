// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/viewer_plaintext.h"

#include <memory>
#include <unistd.h>
#include <utility>

#include "base/files/file_util.h"
#include "base/json/string_escape.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"

#include "croslog/constants.h"
#include "croslog/cursor_util.h"
#include "croslog/log_parser_audit.h"
#include "croslog/log_parser_syslog.h"
#include "croslog/severity.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace croslog {

namespace {

int64_t ToMicrosecondsSinceUnixEpoch(base::Time time) {
  return (time - base::Time::UnixEpoch()).InMicroseconds();
}

}  // anonymous namespace

ViewerPlaintext::ViewerPlaintext(const croslog::Config& config)
    : config_(config) {
  Initialize();
}

// For test
ViewerPlaintext::ViewerPlaintext(const croslog::Config& config,
                                 BootRecords&& boot_logs)
    : config_(config), boot_records_{std::move(boot_logs)} {
  Initialize();
}

void ViewerPlaintext::Initialize() {
  if (!config_.grep.empty()) {
    config_grep_.emplace(config_.grep);
    if (!config_grep_->ok())
      config_grep_.reset();
  }

  if (!config_.after_cursor.empty()) {
    if (ParseCursor(config_.after_cursor, &config_cursor_time_))
      config_cursor_mode_ = CursorMode::NEWER;
    else
      LOG(WARNING) << "Invalid cursor format in 'after-cursor' option.";
  } else if (!config_.cursor.empty()) {
    if (ParseCursor(config_.cursor, &config_cursor_time_))
      config_cursor_mode_ = CursorMode::SAME_AND_NEWER;
    else
      LOG(WARNING) << "Invalid cursor format in 'cursor' option.";
  }

  config_show_cursor_ = config_.show_cursor && !config_.follow;

  config_boot_range_.reset();
  if (config_.boot.has_value()) {
    auto range = boot_records_.GetBootRange(*config_.boot);
    if (range.has_value())
      config_boot_range_.emplace(*range);
  }
}

bool ViewerPlaintext::Run() {
  bool install_change_watcher = config_.follow;
  for (const auto& log_path_str : croslog::kLogSources) {
    base::FilePath path(log_path_str.data());
    if (!base::PathExists(path))
      continue;
    multiplexer_.AddSource(path, std::make_unique<LogParserSyslog>(),
                           install_change_watcher);
  }

  for (const auto& log_path_str : croslog::kAuditLogSources) {
    base::FilePath path(log_path_str.data());
    if (!base::PathExists(path))
      continue;
    multiplexer_.AddSource(path, std::make_unique<LogParserAudit>(),
                           install_change_watcher);
  }

  multiplexer_.AddObserver(this);

  if (config_.lines >= 0) {
    multiplexer_.SetLinesFromLast(config_.lines);
  } else if (config_.follow) {
    multiplexer_.SetLinesFromLast(10);
  }

  ReadRemainingLogs();

  if (config_.follow) {
    // Wait for file changes.
    run_loop_.Run();

    multiplexer_.RemoveObserver(this);
  }

  return true;
}

void ViewerPlaintext::OnLogFileChanged() {
  ReadRemainingLogs();
}

bool ViewerPlaintext::ShouldFilterOutEntry(const LogEntry& e) {
  if (config_cursor_mode_ != CursorMode::UNSPECIFIED) {
    if ((config_cursor_mode_ == CursorMode::NEWER &&
         config_cursor_time_ >= e.time()) ||
        (config_cursor_mode_ == CursorMode::SAME_AND_NEWER &&
         config_cursor_time_ > e.time())) {
      // TODO(yoshiki): Consider the case that multiple logs have the same
      // time.
      return true;
    }
  }

  if (!config_.since.is_null() && e.time() < config_.since)
    return true;

  if (!config_.until.is_null() && e.time() > config_.until)
    return true;

  const std::string& tag = e.tag();
  if (!config_.identifier.empty() && config_.identifier != tag)
    return true;

  const Severity severity = e.severity();
  if (config_.severity != Severity::UNSPECIFIED && config_.severity < severity)
    return true;

  const std::string& message = e.message();
  if (config_grep_.has_value() && !RE2::PartialMatch(message, *config_grep_))
    return true;

  if (config_.boot.has_value()) {
    if (!config_boot_range_.has_value() ||
        !config_boot_range_->Contains(e.time())) {
      return true;
    }
  }

  return false;
}

void ViewerPlaintext::ReadRemainingLogs() {
  base::Time last_shown_log_time;

  while (true) {
    const MaybeLogEntry& e = multiplexer_.Forward();
    if (!e.has_value())
      break;

    // Shoe the last cursor regardless of visibility.
    if (config_show_cursor_)
      last_shown_log_time = e->time();

    if (ShouldFilterOutEntry(*e))
      continue;

    WriteLog(*e);
  }

  if (config_show_cursor_) {
    if (last_shown_log_time.is_null()) {
      multiplexer_.SetLinesFromLast(1);
      const MaybeLogEntry& e = multiplexer_.Forward();
      if (e.has_value())
        last_shown_log_time = e->time();
    }

    if (!last_shown_log_time.is_null()) {
      WriteOutput("-- cursor: ");
      WriteOutput(GenerateCursor(last_shown_log_time));
      WriteOutput("\n");
    }
  }
}

std::vector<std::pair<std::string, std::string>>
ViewerPlaintext::GenerateKeyValues(const LogEntry& e) {
  std::vector<std::pair<std::string, std::string>> kvs;
  kvs.push_back(std::make_pair(
      "PRIORITY", base::NumberToString(static_cast<int>(e.severity()))));
  kvs.push_back(std::make_pair("SYSLOG_IDENTIFIER", e.tag()));

  const std::string& boot_id = GetBootIdAt(e.time());
  if (!boot_id.empty())
    kvs.push_back(std::make_pair("_BOOT_ID", boot_id));

  std::string timestamp =
      base::NumberToString(ToMicrosecondsSinceUnixEpoch(e.time()));
  kvs.push_back(std::make_pair("__REALTIME_TIMESTAMP", timestamp));
  kvs.push_back(std::make_pair("_SOURCE_REALTIME_TIMESTAMP", timestamp));

  if (e.pid() != -1) {
    kvs.push_back(std::make_pair("SYSLOG_PID", base::NumberToString(e.pid())));
    kvs.push_back(std::make_pair("_PID", base::NumberToString(e.pid())));
  }
  kvs.push_back(std::make_pair("MESSAGE", e.message()));
  return kvs;
}

void ViewerPlaintext::WriteLog(const LogEntry& entry) {
  if (config_.output == OutputMode::EXPORT)
    return WriteLogInExportFormat(entry);
  if (config_.output == OutputMode::JSON)
    return WriteLogInJsonFormat(entry);

  const std::string& s = entry.entire_line();
  WriteOutput(s);
  WriteOutput("\n");
}

void ViewerPlaintext::WriteLogInExportFormat(const LogEntry& entry) {
  const auto&& kvs = GenerateKeyValues(entry);
  for (const auto& kv : kvs) {
    WriteOutput(kv.first);
    WriteOutput("=");
    WriteOutput(kv.second);
    WriteOutput("\n");
  }
  WriteOutput("\n");
}

std::string ViewerPlaintext::GetBootIdAt(base::Time time) {
  const auto& boot_ranges = boot_records_.boot_ranges();
  DCHECK_GE(cache_boot_range_index_, -1);
  DCHECK_LT(cache_boot_range_index_, static_cast<int>(boot_ranges.size()));

  // First, tries to reuse the index used at the last time. In most case, the
  // logs are read sequentially and the boot id is likely to be same as the
  // previous.
  if (cache_boot_range_index_ != -1 &&
      boot_ranges[cache_boot_range_index_].Contains(time)) {
    return boot_ranges[cache_boot_range_index_].boot_id();
  }

  // Otherwise, searches the boot id sequentially from the boot log.
  for (int i = boot_ranges.size() - 1; i >= 0; i--) {
    const auto& boot_range = boot_ranges[i];
    if (boot_range.Contains(time)) {
      cache_boot_range_index_ = i;
      return boot_range.boot_id();
    }
  }
  return base::EmptyString();
}

void ViewerPlaintext::WriteLogInJsonFormat(const LogEntry& entry) {
  const auto&& kvs = GenerateKeyValues(entry);
  bool first = true;
  WriteOutput("{");
  for (const auto& kv : kvs) {
    std::string escaped_value;
    bool ret_value = base::EscapeJSONString(kv.second, true, &escaped_value);
    if (!ret_value)
      escaped_value = "<<INVALID>>";

    if (!first)
      WriteOutput(", \"");
    else
      WriteOutput("\"");
    // All keys are hard-corded and unnecessary to escape.
    WriteOutput(kv.first);
    WriteOutput("\": ");
    WriteOutput(escaped_value);
    first = false;
  }
  WriteOutput("}\n");
}

void ViewerPlaintext::WriteOutput(base::StringPiece str) {
  bool write_stdout_result = base::WriteFileDescriptor(STDOUT_FILENO, str);
  CHECK(write_stdout_result);
}

}  // namespace croslog
