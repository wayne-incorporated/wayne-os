// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_ERROR_H_
#define MINIOS_ERROR_H_

#include <string>

#include <brillo/errors/error.h>

namespace minios {

extern const char kErrorDomain[];

namespace error {
extern const char kCannotReset[];
extern const char kFailedGoToNextScreen[];
extern const char kFailedGoToPrevScreen[];
extern const char kWaitForStateTimeout[];
};  // namespace error

class Error {
 public:
  // Add a dbus error to the error chain.
  static void AddTo(brillo::ErrorPtr* error,
                    const base::Location& location,
                    const std::string& code,
                    const std::string& message);

  Error(const Error&) = delete;
  Error& operator=(const Error&) = delete;
};

}  // namespace minios

#endif  // MINIOS_ERROR_H_
