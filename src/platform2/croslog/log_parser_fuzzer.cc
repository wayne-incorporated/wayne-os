// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include <base/logging.h>

#include "croslog/log_parser_audit.h"
#include "croslog/log_parser_syslog.h"

namespace croslog {

namespace {

struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOG_FATAL); }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  const std::string data_string(reinterpret_cast<const char*>(data), size);

  LogParserAudit().Parse(std::string(data_string));
  LogParserSyslog().Parse(std::string(data_string));

  return 0;
}

}  // namespace croslog
