// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_KEYMASTER_LOGGER_H_
#define ARC_KEYMASTER_KEYMASTER_LOGGER_H_

#include <keymaster/logger.h>

namespace arc {
namespace keymaster {

// Logger implementation that forwards messages to Chrome OS's logging system.
class KeymasterLogger : public ::keymaster::Logger {
 public:
  KeymasterLogger();
  KeymasterLogger(const KeymasterLogger&) = delete;
  KeymasterLogger& operator=(const KeymasterLogger&) = delete;

  ~KeymasterLogger() override = default;

  int log_msg(LogLevel level, const char* fmt, va_list args) const override;
};

// Expose the TrimFilePath function in the anonymous namespace for testing.
const char* TrimFilePathForTesting(const char* logMessage);

}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_KEYMASTER_LOGGER_H_
