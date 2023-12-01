// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_LOG_PARSER_SYSLOG_H_
#define CROSLOG_LOG_PARSER_SYSLOG_H_

#include "croslog/log_parser.h"

#include <string>

namespace croslog {

class LogParserSyslog : public LogParser {
 public:
  LogParserSyslog();
  LogParserSyslog(const LogParserSyslog&) = delete;
  LogParserSyslog& operator=(const LogParserSyslog&) = delete;

 private:
  MaybeLogEntry ParseInternal(std::string&& entire_line) override;
};

}  // namespace croslog

#endif  // CROSLOG_LOG_PARSER_SYSLOG_H_
