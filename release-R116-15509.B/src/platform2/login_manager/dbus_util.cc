// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/dbus_util.h"

#include <brillo/errors/error_codes.h>

namespace login_manager {

brillo::ErrorPtr CreateError(const std::string& code,
                             const std::string& message) {
  return brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain, code,
                               message);
}

}  // namespace login_manager
