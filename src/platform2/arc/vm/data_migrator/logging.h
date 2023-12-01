// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_DATA_MIGRATOR_LOGGING_H_
#define ARC_VM_DATA_MIGRATOR_LOGGING_H_

#include <string>

#include <base/logging.h>

namespace arc::data_migrator {

// A helper function to redact file paths in the log.
std::string RedactAndroidDataPaths(const std::string& input_string);

// Handles any log messages from the arcvm-data-migrator process.
// Redacts the file paths in them and writes them to the syslog.
bool LogMessageHandler(logging::LogSeverity severity,
                       const char* file,
                       int line,
                       size_t message_start,
                       const std::string& message);

}  // namespace arc::data_migrator

#endif  // ARC_VM_DATA_MIGRATOR_LOGGING_H_
