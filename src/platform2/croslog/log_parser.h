// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_LOG_PARSER_H_
#define CROSLOG_LOG_PARSER_H_

#include "croslog/log_entry.h"

#include <optional>
#include <string>

namespace croslog {

using MaybeLogEntry = std::optional<LogEntry>;

class LogParser {
 public:
  virtual ~LogParser() {}

  MaybeLogEntry Parse(std::string&& entire_line);

 protected:
  virtual MaybeLogEntry ParseInternal(std::string&& entire_line) = 0;
};

}  // namespace croslog

#endif  // CROSLOG_LOG_PARSER_H_
