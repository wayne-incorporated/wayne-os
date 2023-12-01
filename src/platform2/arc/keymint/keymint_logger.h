// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMINT_KEYMINT_LOGGER_H_
#define ARC_KEYMINT_KEYMINT_LOGGER_H_

#include <keymaster/logger.h>

namespace arc::keymint {

// Logger implementation that forwards messages to Chrome OS's logging system.
class KeyMintLogger : public ::keymaster::Logger {
 public:
  KeyMintLogger();
  KeyMintLogger(const KeyMintLogger&) = delete;
  KeyMintLogger& operator=(const KeyMintLogger&) = delete;

  ~KeyMintLogger() override = default;

  int log_msg(LogLevel level, const char* fmt, va_list args) const override;
};

// Expose the TrimFilePath function in the anonymous namespace for testing.
const char* TrimFilePathForTesting(const char* logMessage);

}  // namespace arc::keymint

#endif  // ARC_KEYMINT_KEYMINT_LOGGER_H_
