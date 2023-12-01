// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_LOG_PARSER_AUDIT_H_
#define CROSLOG_LOG_PARSER_AUDIT_H_

#include "croslog/log_parser.h"

#include <string>

namespace croslog {

class LogParserAudit : public LogParser {
 public:
  LogParserAudit();
  LogParserAudit(const LogParserAudit&) = delete;
  LogParserAudit& operator=(const LogParserAudit&) = delete;

 private:
  MaybeLogEntry ParseInternal(std::string&& entire_line);
};

}  // namespace croslog

#endif  // CROSLOG_LOG_PARSER_AUDIT_H_
