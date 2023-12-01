// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// <syslog.h> defines LOG_INFO, LOG_WARNING macros that conflicts with
// base/logging.h
#include <syslog.h>
#undef LOG_INFO
#undef LOG_WARNING

#include <base/logging.h>

namespace arc {
namespace {

int LoggingToSyslogPriority(int severity) {
  switch (severity) {
    case logging::LOGGING_VERBOSE:
      return 7;  // LOG_DEBUG
    case logging::LOGGING_INFO:
      return 6;  // LOG_INFO
    case logging::LOGGING_WARNING:
      return 4;  // LOG_WARNING
    case logging::LOGGING_ERROR:
      return 3;  // LOG_ERR
    case logging::LOGGING_FATAL:
      return 2;  // LOG_CRIT
    default:
      return 7;  // LOG_DEBUG
  }
}

bool RedirectMessage(int severity,
                     const char* file,
                     int line,
                     size_t message_start,
                     const std::string& str_newline) {
  syslog(LoggingToSyslogPriority(severity), "%s", str_newline.c_str());
  return true;
}

__attribute__((constructor)) void SetupLogging() {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_NONE;
  settings.log_format = logging::LogFormat::LOG_FORMAT_CHROME;
  logging::InitLogging(settings);

  openlog("libvda", LOG_NDELAY | LOG_PID, LOG_USER);
  logging::SetLogMessageHandler(&RedirectMessage);
}

__attribute__((destructor)) void TeardownLogging() {
  closelog();
}

}  // namespace
}  // namespace arc
