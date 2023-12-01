// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_entry.h"

namespace croslog {

LogEntry::LogEntry(base::Time time,
                   Severity severity,
                   std::string&& tag,
                   int pid,
                   std::string&& message,
                   std::string&& entire_line)
    : time_(time),
      severity_(severity),
      tag_(std::move(tag)),
      pid_(pid),
      message_(std::move(message)),
      entire_line_(std::move(entire_line)) {}

void LogEntry::AppendLinesToMessage(const std::list<std::string>& lines) {
  // Calculates the size of buffer to expand.
  size_t lines_size = 0;
  for (const auto& line : lines) {
    lines_size += line.size() + 1;
  }

  // Pre-reserves buffer for efficiency.
  message_.reserve(message_.size() + lines_size);
  entire_line_.reserve(entire_line_.size() + lines_size);

  // Appends lines
  for (const auto& line : lines) {
    message_.append("\n", 1);
    message_.append(line);

    entire_line_.append("\n", 1);
    entire_line_.append(line);
  }
}

}  // namespace croslog
