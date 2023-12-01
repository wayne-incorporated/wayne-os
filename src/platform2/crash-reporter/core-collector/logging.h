// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CORE_COLLECTOR_LOGGING_H_
#define CRASH_REPORTER_CORE_COLLECTOR_LOGGING_H_

#include <errno.h>

#include <cstring>  // For strerror.
#include <iostream>
#include <string>

#define LOG_ERROR ErrorMessage()
#define PLOG_ERROR ErrorMessage(strerror(errno))

extern const char* g_exec_name;

class ErrorMessage {
 public:
  ErrorMessage() : ErrorMessage(std::string()) {}

  explicit ErrorMessage(const std::string& os_error) : os_error_(os_error) {
    std::cerr << g_exec_name << ": ";
  }

  ~ErrorMessage() {
    if (!os_error_.empty())
      std::cerr << ": " << os_error_;

    std::cerr << ".\n";
  }

 private:
  const std::string os_error_;
};

template <typename Type>
inline const ErrorMessage& operator<<(const ErrorMessage& message,
                                      const Type& value) {
  std::cerr << value;
  return message;
}

#endif  // CRASH_REPORTER_CORE_COLLECTOR_LOGGING_H_
