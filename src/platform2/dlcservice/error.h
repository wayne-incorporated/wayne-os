// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_ERROR_H_
#define DLCSERVICE_ERROR_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <brillo/errors/error.h>

namespace dlcservice {

extern const char kDlcErrorDomain[];

namespace error {
extern const char kFailedToCreateDirectory[];
extern const char kFailedInstallInUpdateEngine[];
extern const char kFailedInternal[];
extern const char kFailedToVerifyImage[];
extern const char kFailedToMountImage[];
extern const char kFailedCreationDuringHibernateResume[];
};  // namespace error

class Error {
 public:
  // Returns the D-Bus error object with error code and error message set.
  static brillo::ErrorPtr Create(const base::Location& location,
                                 const std::string& code,
                                 const std::string& msg);

  // Returns the D-Bus error object with error code and error message set.
  static brillo::ErrorPtr CreateInternal(const base::Location& location,
                                         const std::string& code,
                                         const std::string& message);

  // Add a dbus error to the error chain.
  static void AddTo(brillo::ErrorPtr* error,
                    const base::Location& location,
                    const std::string& code,
                    const std::string& message);

  // Add an internal error to the error chain.
  static void AddInternalTo(brillo::ErrorPtr* error,
                            const base::Location& location,
                            const std::string& code,
                            const std::string& message);

  // Returns a string representation of D-Bus error object used to help logging.
  static std::string ToString(const brillo::ErrorPtr& err);

  // Returns the first error code of a chain of errors.
  static std::string GetRootErrorCode(const brillo::ErrorPtr& error);

  // Returns the first error code of a chain of errors with a dlcservice error
  // code. If no dlcservice error code is found, it returns |kErrorInternal|.
  static std::string GetErrorCode(const brillo::ErrorPtr& error);

  // Convert a chain of errors into a single error in the DBus domain. The first
  // error in the chain which is in the DBus domain, will be returned. If no
  // error is in the DBus domain, return |kErrorInternal|.
  static void ConvertToDbusError(brillo::ErrorPtr* error);

  Error(const Error&) = delete;
  Error& operator=(const Error&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_ERROR_H_
