// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_LOG_ENTRY_READER_H_
#define CROSLOG_LOG_ENTRY_READER_H_

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"

#include "croslog/log_entry.h"
#include "croslog/log_line_reader.h"
#include "croslog/log_parser.h"

namespace croslog {

/*
 * This class is responsible for
 * - Parses line(s) with the given parser and returns a LogEntry.
 * - Supports multi-line logs.
 */
class LogEntryReader {
 public:
  LogEntryReader(base::FilePath log_file,
                 std::unique_ptr<LogParser> parser_in,
                 bool install_change_watcher);

  LogEntryReader(const LogEntryReader&) = delete;
  LogEntryReader& operator=(const LogEntryReader&) = delete;

  // Returns the parsed previous entry, or a nullopt, if the current position
  // reaches the beginning of the file.
  MaybeLogEntry GetPreviousEntry();
  // Returns the parsed next entry, or a nullopt, if the current position
  // reaches the current end of the file.
  MaybeLogEntry GetNextEntry();

  // Moves the current position to the current end of the file.
  void SetPositionLast();

  // Returns the file path of the target.
  const base::FilePath& file_path() const { return file_path_; }

  // Add a observer to retrieve file change events.
  void AddObserver(LogLineReader::Observer* obs);
  // Remove a observer to retrieve file change events.
  void RemoveObserver(LogLineReader::Observer* obs);

 private:
  base::FilePath file_path_;
  LogLineReader line_reader_;
  MaybeLogEntry next_entry_;
  std::unique_ptr<LogParser> parser_;
};

}  // namespace croslog

#endif  // CROSLOG_LOG_ENTRY_READER_H_
