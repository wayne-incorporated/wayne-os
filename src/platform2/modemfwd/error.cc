// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/error.h"

#include <unordered_set>

#include <base/check.h>
#include <base/strings/stringprintf.h>
#include <brillo/errors/error_codes.h>
#include <dbus/modemfwd/dbus-constants.h>

namespace modemfwd {

const char kModemfwdErrorDomain[] = "modemfwd";
namespace error {
const char kDlcServiceReturnedErrorOnGetDlcState[] =
    "dlcServiceReturnedErrorOnFailedToGetDlcState";
const char kDlcServiceReturnedErrorOnGetExistingDlcs[] =
    "dlcServiceReturnedErrorOnFailedToGetExistingDlcs";
const char kDlcServiceReturnedErrorOnInstall[] =
    "dlcServiceReturnedErrorOnInstall";
const char kDlcServiceReturnedErrorOnPurge[] = "dlcServiceReturnedErrorOnPurge";
const char kUnexpectedDlcState[] = "unexpectedDlcState";
const char kUnexpectedEmptyDlcId[] = "unexpectedEmptyDlcId";
const char kUnexpectedEmptyVariant[] = "unexpectedEmptyVariant";
const char kTimeoutWaitingForInstalledState[] = "unexpectedInstallStep";
const char kTimeoutWaitingForDlcService[] = "timeoutWaitingForDlcService";
const char kTimeoutWaitingForDlcInstall[] = "timeoutWaitingForDlcInstall";

}  // namespace error

// static
brillo::ErrorPtr Error::Create(const base::Location& location,
                               const std::string& code,
                               const std::string& msg) {
  return brillo::Error::Create(location, kModemfwdErrorDomain, code, msg);
}

// static
void Error::AddTo(brillo::ErrorPtr* error,
                  const base::Location& location,
                  const std::string& code,
                  const std::string& message) {
  brillo::Error::AddTo(error, location, kModemfwdErrorDomain, code, message);
}

// static
brillo::ErrorPtr Error::CreateFromDbusError(brillo::Error* dbus_error) {
  if (!dbus_error)
    return brillo::Error::Create(FROM_HERE, kModemfwdErrorDomain, "", "");

  return brillo::Error::Create(dbus_error->GetLocation(),
                               dbus_error->GetDomain(), dbus_error->GetCode(),
                               dbus_error->GetMessage());
}

}  // namespace modemfwd
