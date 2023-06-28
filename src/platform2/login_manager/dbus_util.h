// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_DBUS_UTIL_H_
#define LOGIN_MANAGER_DBUS_UTIL_H_

#include <string>

#include <brillo/errors/error.h>

namespace login_manager {

// Creates a D-Bus error instance.
brillo::ErrorPtr CreateError(const std::string& code,
                             const std::string& message);

// Creates a D-Bus error, but also logs the message. Written as a macro
// to preserve file and line information.
#define DBUS_ERROR_WITH_LOG(log, code, message) \
  ({                                            \
    constexpr char __message[] = (message);     \
    LOG(log) << __message;                      \
    CreateError((code), __message);             \
  })

#define CREATE_ERROR_AND_LOG(code, message) \
  DBUS_ERROR_WITH_LOG(ERROR, (code), (message))
#define CREATE_WARNING_AND_LOG(code, message) \
  DBUS_ERROR_WITH_LOG(WARNING, (code), (message))

}  // namespace login_manager

#endif  // LOGIN_MANAGER_DBUS_UTIL_H_
