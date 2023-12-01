// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_entry_reader.h"

#include <list>
#include <optional>
#include <utility>

#include "base/strings/string_util.h"

#include "croslog/log_parser_syslog.h"

namespace croslog {

LogEntryReader::LogEntryReader(base::FilePath log_file,
                               std::unique_ptr<LogParser> parser_in,
                               bool install_change_watcher)
    : file_path_(log_file),
      line_reader_(install_change_watcher ? LogLineReader::Backend::FILE_FOLLOW
                                          : LogLineReader::Backend::FILE),
      parser_(std::move(parser_in)) {
  line_reader_.OpenFile(std::move(log_file));
}

MaybeLogEntry LogEntryReader::GetPreviousEntry() {
  // If we have looked ahead, go back to the current position and invalidate the
  // cache.
  if (next_entry_.has_value()) {
    line_reader_.Backward();
    next_entry_.reset();
  }

  std::list<std::string> lines;
  // Reads preceding lines until a parsable line, which should be the first
  // line of log entry, comes.
  while (true) {
    auto [line, result] = line_reader_.Backward();
    if (result != LogLineReader::ReadResult::NO_ERROR) {
      // No more entry or failed to read
      return std::nullopt;
    }

    MaybeLogEntry entry = parser_->Parse(std::move(line));
    if (entry.has_value()) {
      if (!lines.empty())
        entry->AppendLinesToMessage(lines);
      return entry;
    }

    lines.push_front(std::move(line));
  }
}

MaybeLogEntry LogEntryReader::GetNextEntry() {
  MaybeLogEntry entry;
  if (!next_entry_.has_value()) {
    // Reads a next lines with skipping non-parsable lines.
    while (true) {
      auto [line, result] = line_reader_.Forward();
      if (result != LogLineReader::ReadResult::NO_ERROR) {
        // No more entry or failed to read
        return std::nullopt;
      }

      MaybeLogEntry maybe_entry = parser_->Parse(std::move(line));
      if (!maybe_entry.has_value()) {
        // Parse failed. Go to the next line.
        continue;
      }

      entry.emplace(std::move(*maybe_entry));
      break;
    }
  } else {
    entry.emplace(std::move(*next_entry_));
    next_entry_.reset();
  }

  std::list<std::string> lines;
  // Reads succeeding lines until a parsable line, which should be the first
  // line of the next log entry, comes.
  while (true) {
    auto [line, result] = line_reader_.Forward();
    if (result != LogLineReader::ReadResult::NO_ERROR) {
      // No more entry
      break;
    }

    MaybeLogEntry maybe_entry = parser_->Parse(std::move(line));
    if (maybe_entry.has_value()) {
      next_entry_.emplace(std::move(*maybe_entry));
      break;
    }

    lines.push_back(std::move(line));
  }

  entry->AppendLinesToMessage(lines);
  return entry;
}

void LogEntryReader::SetPositionLast() {
  line_reader_.SetPositionLast();
}

void LogEntryReader::AddObserver(LogLineReader::Observer* obs) {
  line_reader_.AddObserver(obs);
}

void LogEntryReader::RemoveObserver(LogLineReader::Observer* obs) {
  line_reader_.RemoveObserver(obs);
}

}  // namespace croslog
