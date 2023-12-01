// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/keymaster_logger.h"

#include <string.h>
#include <string>

#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace arc {
namespace keymaster {

namespace {

constexpr char kLogTag[] = "ArcKeymaster ";

// Removes the file path from a given log message.
//
// Messages coming from the keymaster logger may include a file path, which is
// verbose and not very relevant. This method trims it out from the message to
// avoid the redundancy.
//
// More specifically, incoming messages have the following format:
//   </full/path/to/caller.cpp>, Line <number>: <actual log message>
//
// And this function trims it as follows:
//   <caller.cpp>, Line <number>: <actual log message>
const char* TrimFilePath(const char* logMessage) {
  const char* file_name_start = std::strrchr(logMessage, '/');
  const char* file_name_end = std::strstr(logMessage, ", Line ");

  const char* trim_start = file_name_start ? file_name_start + 1 : logMessage;
  const char* fallback_start = file_name_end ? file_name_end + 2 : logMessage;
  return trim_start < fallback_start ? trim_start : fallback_start;
}

}  // anonymous namespace

KeymasterLogger::KeymasterLogger() {
  set_instance(this);
}

int KeymasterLogger::log_msg(LogLevel level,
                             const char* fmt,
                             va_list args) const {
  std::string msg = base::StringPrintV(TrimFilePath(fmt), args);

  switch (level) {
    case DEBUG_LVL:
    case INFO_LVL:
      LOG(INFO) << kLogTag << msg;
      break;
    case WARNING_LVL:
      LOG(WARNING) << kLogTag << msg;
      break;
    case ERROR_LVL:
    case SEVERE_LVL:
      LOG(ERROR) << kLogTag << msg;
      break;
  }

  return 0;
}

const char* TrimFilePathForTesting(const char* logMessage) {
  return TrimFilePath(logMessage);
}

}  // namespace keymaster
}  // namespace arc
