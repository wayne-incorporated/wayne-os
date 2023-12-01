// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/logging.h"

// <syslog.h> defines LOG_INFO and LOG_WARNING macros that conflict with
// base/logging.h.
#include <syslog.h>
#undef LOG_INFO
#undef LOG_WARNING

#include <string>

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

namespace arc::data_migrator {

namespace {

// Regexp used to find file paths that need to be redacted in the log.
constexpr LazyRE2 kRegexp = {
    // We support the absolute paths in the migration source and the
    // destination, and relative paths from the migration root. We assume that
    // the relative paths are preceded with a space, a double quote, or a colon.
    R"((/tmp/arcvm-data-migration-mount/|)"
    R"(/home/root/[0-9a-f]{40}/android-data/data/|[\s":]))"
    // The following paths will be redacted as follows:
    // - app/foo/bar -> app/***
    // - data/foo/bar -> data/***
    // - media/0/Android/{data,obb}/foo/bar -> media/0/Android/{data,obb}/***
    // - media/0/foo/bar -> media/0/***
    // - user/0/foo/bar -> user/0/***
    // - user_de/0/foo/bar -> user_de/0/***
    // We assume that the paths to be redacted doesn't include newlines, double
    // quotes or colons.
    R"((app|data|media/0(/Android/(data|obb))?|user(_de)?/0)/[^\n":]+)"};

}  // namespace

std::string RedactAndroidDataPaths(const std::string& input) {
  std::string result = input;
  // '\1' is the prefix and '\2' is the relative path from the migration root.
  RE2::Replace(&result, *kRegexp, R"(\1\2/***)");
  return result;
}

bool LogMessageHandler(logging::LogSeverity severity,
                       const char* file,
                       int line,
                       size_t message_start,
                       const std::string& message) {
  int priority = 7;  // LOG_DEBUG

  switch (severity) {
    case logging::LOGGING_INFO:
      priority = 6;  // LOG_INFO
      break;

    case logging::LOGGING_WARNING:
      priority = 4;  // LOG_WARNING
      break;

    case logging::LOGGING_ERROR:
      priority = 3;  // LOG_ERR
      break;

    case logging::LOGGING_FATAL:
      priority = 2;  // LOG_CRIT
      break;

    default:
      break;
  }

  std::string redacted_message = RedactAndroidDataPaths(message);
  syslog(priority, "%s", redacted_message.c_str());
  return true;
}

}  // namespace arc::data_migrator
