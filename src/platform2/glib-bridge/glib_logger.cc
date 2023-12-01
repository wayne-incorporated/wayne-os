// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "glib-bridge/glib_logger.h"

#include <glib.h>

#include <optional>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace glib_bridge {

// Used for testing.
uint64_t g_num_logs = 0;

namespace {

// Structured logging uses syslog priority levels. See
// http://man7.org/linux/man-pages/man3/syslog.3.html#DESCRIPTION
// Note that LOG_ERR is used in g_error which is expected to
// abort execution, so the levels seem to be one off from normal
// Chrome usage.
// Also, since there are conflicts between the syslog macros and
// Chrome log levels, these are given as bare ints.
logging::LogSeverity GetLogSeverity(int priority) {
  switch (priority) {
    case 0:  // EMERG
    case 1:  // ALERT
    case 2:  // CRIT
    case 3:  // ERROR
      return logging::LOGGING_FATAL;
    case 4:  // WARNING
      return logging::LOGGING_ERROR;
    case 5:  // NOTICE
      return logging::LOGGING_WARNING;
    case 6:  // INFO
      return logging::LOGGING_INFO;
    case 7:  // DEBUG
    default:
      return logging::LOGGING_VERBOSE;
  }
}

std::optional<int> ParseIntField(const char* value) {
  int parsed;
  if (base::StringToInt(value, &parsed))
    return parsed;
  return std::nullopt;
}

GLogWriterOutput LogHandler(GLogLevelFlags log_level,
                            const GLogField* fields,
                            gsize n_fields,
                            gpointer user_data) {
  std::optional<std::string> message;
  std::optional<int> priority;
  std::optional<std::string> code_file;
  std::optional<int> code_line;
  std::optional<int> log_errno;

  for (int i = 0; i < n_fields; i++) {
    const char* key = fields[i].key;
    const char* value = static_cast<const char*>(fields[i].value);
    if (strcmp(key, "MESSAGE") == 0) {
      message = std::string(value);
    } else if (strcmp(key, "PRIORITY") == 0) {
      priority = ParseIntField(value);
    } else if (strcmp(key, "CODE_FILE") == 0) {
      code_file = std::string(value);
    } else if (strcmp(key, "CODE_LINE") == 0) {
      code_line = ParseIntField(value);
    } else if (strcmp(key, "ERRNO") == 0) {
      log_errno = ParseIntField(value);
    }
    // Possibly explore using key CODE_FUNC as well.
  }

  // glib guarantees that logs will have a message and priority.
  CHECK(message.has_value() && priority.has_value());

  // Give defaults for code file/line if they were not found.
  if (!code_file.has_value())
    code_file = std::string(__FILE__);
  if (!code_line.has_value())
    code_line = 0;

  logging::LogSeverity severity = GetLogSeverity(priority.value());

  if (log_errno.has_value()) {
    logging::ErrnoLogMessage logger(code_file.value().c_str(),
                                    code_line.value(), severity,
                                    log_errno.value());
    logger.stream() << message.value();
  } else {
    logging::LogMessage logger(code_file.value().c_str(), code_line.value(),
                               severity);
    logger.stream() << message.value();
  }

  g_num_logs++;
  return G_LOG_WRITER_HANDLED;
}

}  // namespace

void ForwardLogs() {
  g_log_set_writer_func(LogHandler, nullptr, nullptr);
}

}  // namespace glib_bridge
