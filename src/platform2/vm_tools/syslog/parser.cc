// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/parser.h"

#include <time.h>

#include <cinttypes>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

using std::string;

namespace vm_tools {
namespace syslog {
namespace {

// Converts a priority level into a severity level.
vm_tools::LogSeverity PriorityToSeverity(unsigned int priority) {
  // We can't use the symbolic names here because LOG_INFO, LOG_WARNING, etc.
  // all conflict with the base logging macros that have the same name.
  switch (priority & 0x7) {
    case 0:
      return vm_tools::EMERGENCY;
    case 1:
      return vm_tools::ALERT;
    case 2:
      return vm_tools::CRITICAL;
    case 3:
      return vm_tools::ERROR;
    case 4:
      return vm_tools::WARNING;
    case 5:
      return vm_tools::NOTICE;
    case 6:
      return vm_tools::INFO;
    case 7:
      return vm_tools::DEBUG;
    default:
      return vm_tools::MISSING;
  }
}

// Stores the current time in UTC in |timestamp|.
void GetCurrentTime(vm_tools::Timestamp* timestamp) {
  struct timespec ts;

  // This should never fail on a well-behaved system.
  int ret = clock_gettime(CLOCK_REALTIME, &ts);
  DCHECK_EQ(ret, 0);
  timestamp->set_seconds(ts.tv_sec);
  timestamp->set_nanos(ts.tv_nsec);
}

}  // namespace

size_t ParseSyslogPriority(const char* buf, vm_tools::LogSeverity* severity) {
  CHECK(buf);
  CHECK(severity);
  unsigned int priority;
  size_t pos = 0;
  // The priority cannot take up more than 5 characters.  If there is an
  // un-terminated '<' followed by a valid unsigned int, sscanf will return 1
  // but pos will still be 0.
  if (sscanf(buf, "<%u>%zn", &priority, &pos) == 1 && pos <= 5 && pos > 0) {
    // We successfully read out the priority and it is valid.
    *severity = PriorityToSeverity(priority);
    return pos;
  }

  return 0;
}

size_t ParseSyslogTimestamp(const char* buf, vm_tools::Timestamp* timestamp) {
  CHECK(buf);
  CHECK(timestamp);

  // Get the current time.
  GetCurrentTime(timestamp);

  // Fill the struct with the current time.
  struct tm tm;
  time_t current_time = timestamp->seconds();
  localtime_r(&current_time, &tm);

  char* cur = strptime(buf, "%b %e %T", &tm);
  if (cur != nullptr) {
    // Successfully parsed the timestamp.
    time_t seconds = timelocal(&tm);
    if (seconds >= 0) {
      timestamp->set_seconds(seconds);
      timestamp->set_nanos(0);

      return cur - buf;
    }
  }

  return 0;
}

bool ParseSyslogRecord(const char* buf,
                       size_t len,
                       vm_tools::LogRecord* record) {
  CHECK(buf);
  CHECK(record);

  // Default to NOTICE if we cannot parse the priority.
  vm_tools::LogSeverity severity = vm_tools::NOTICE;
  size_t pos = ParseSyslogPriority(buf, &severity);
  record->set_severity(severity);

  if (pos != 0) {
    // Successfully parsed a priority value.  Attempt to parse the timestamp.
    pos += ParseSyslogTimestamp(&buf[pos], record->mutable_timestamp());
  } else {
    // Failed to parse a priority value.  Default to the current time.
    GetCurrentTime(record->mutable_timestamp());
  }

  if (len <= pos) {
    // Ignore messages with no content.
    record->Clear();
    return false;
  }

  // Whatever is left is the content.
  record->set_content(&buf[pos], len - pos);

  return true;
}

}  // namespace syslog
}  // namespace vm_tools
