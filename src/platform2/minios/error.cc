// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/error.h"

#include <brillo/errors/error.h>

namespace minios {

const char kErrorDomain[] = "minios";

namespace error {
const char kCannotReset[] = "cannotResetMiniOS";
const char kFailedGoToNextScreen[] = "failedGoToNextScreen";
const char kFailedGoToPrevScreen[] = "failedGoToPrevScreen";
const char kWaitForStateTimeout[] = "waitForStateTimedOut";
}  // namespace error

void Error::AddTo(brillo::ErrorPtr* error,
                  const base::Location& location,
                  const std::string& code,
                  const std::string& message) {
  brillo::Error::AddTo(error, location, kErrorDomain, code, message);
}

}  // namespace minios
