// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/scrubber.h"

#include <stdint.h>
#include <syslog.h>
#include <time.h>

#include <base/strings/stringprintf.h>
#include <base/strings/utf_string_conversion_utils.h>
#include <base/third_party/icu/icu_utf.h>

using std::string;

namespace vm_tools {
namespace syslog {
namespace {

// Everything is logged with the LOG_USER facility.
constexpr uint8_t kFacility = LOG_USER;

// Used to replace unknown values.
constexpr uint32_t kUnicodeReplacementChar = 0xfffd;

bool IsControlCharacter(uint32_t code_point) {
  return code_point < 0x20 || (code_point >= 0x7f && code_point < 0xa0);
}

}  // namespace

string ParseProtoSeverity(vm_tools::LogSeverity severity) {
  uint8_t priority;

  switch (severity) {
    case vm_tools::EMERGENCY:
      priority = LOG_EMERG;
      break;
    case vm_tools::ALERT:
      priority = LOG_ALERT;
      break;
    case vm_tools::CRITICAL:
      priority = LOG_CRIT;
      break;
    case vm_tools::ERROR:
      priority = LOG_ERR;
      break;
    case vm_tools::WARNING:
      priority = LOG_WARNING;
      break;
    case vm_tools::NOTICE:
      priority = LOG_NOTICE;
      break;
    case vm_tools::INFO:
      priority = LOG_INFO;
      break;
    case vm_tools::DEBUG:
      priority = LOG_DEBUG;
      break;
    case vm_tools::MISSING:
    default:
      // Use NOTICE for missing severity.
      priority = LOG_NOTICE;
      break;
  }

  return base::StringPrintf("<%u>", priority | kFacility);
}

string ParseProtoTimestamp(const vm_tools::Timestamp& timestamp) {
  char buf[256];
  struct tm tm;
  time_t seconds = timestamp.seconds();
  if (localtime_r(&seconds, &tm) == nullptr) {
    return string();
  }

  size_t ret = strftime(buf, sizeof(buf), "%b %e %T", &tm);
  buf[ret] = '\0';

  return string(buf);
}

string ScrubProtoContent(const string& content) {
  string result;

  for (size_t idx = 0; idx < content.size(); ++idx) {
    base_icu::UChar32 code_point;
    if (!base::ReadUnicodeCharacter(content.c_str(), content.size(), &idx,
                                    &code_point)) {
      // Not a valid code point.  Replace it.
      code_point = kUnicodeReplacementChar;
    }

    if (!base::IsValidCharacter(code_point) || IsControlCharacter(code_point)) {
      base::StringAppendF(&result, "#%03o", code_point);
    } else {
      // We have a valid, non-control code point.
      base::WriteUnicodeCharacter(code_point, &result);
    }
  }

  return result;
}

}  // namespace syslog
}  // namespace vm_tools
