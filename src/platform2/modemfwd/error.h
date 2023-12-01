// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_ERROR_H_
#define MODEMFWD_ERROR_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <brillo/errors/error.h>

namespace modemfwd {

extern const char kModemfwdErrorDomain[];

namespace error {
extern const char kDlcServiceReturnedErrorOnGetDlcState[];
extern const char kDlcServiceReturnedErrorOnGetExistingDlcs[];
extern const char kDlcServiceReturnedErrorOnInstall[];
extern const char kDlcServiceReturnedErrorOnPurge[];
extern const char kUnexpectedDlcState[];
extern const char kUnexpectedEmptyDlcId[];
extern const char kUnexpectedEmptyVariant[];
extern const char kTimeoutWaitingForInstalledState[];
extern const char kTimeoutWaitingForDlcService[];
extern const char kTimeoutWaitingForDlcInstall[];
};  // namespace error

class Error {
 public:
  // Returns a brillo error object with error code and error message set.
  static brillo::ErrorPtr Create(const base::Location& location,
                                 const std::string& code,
                                 const std::string& msg);

  // Add an error to the error chain.
  static void AddTo(brillo::ErrorPtr* error,
                    const base::Location& location,
                    const std::string& code,
                    const std::string& message);

  // Returns a brillo error object with error details extracted from a dbus
  // error.
  static brillo::ErrorPtr CreateFromDbusError(brillo::Error* dbus_error);

  Error(const Error&) = delete;
  Error& operator=(const Error&) = delete;
};

}  // namespace modemfwd

#endif  // MODEMFWD_ERROR_H_
