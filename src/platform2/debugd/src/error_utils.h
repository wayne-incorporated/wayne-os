// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_ERROR_UTILS_H_
#define DEBUGD_SRC_ERROR_UTILS_H_

#include <base/location.h>
#include <base/posix/safe_strerror.h>
#include <brillo/errors/error.h>
#include <brillo/errors/error_codes.h>

// These are provided as macros because providing them as functions
// would cause FROM_HERE to expand to the same value everywhere, which
// impedes debugging.

#define DEBUGD_ADD_ERROR(error, code, message)                            \
  brillo::Error::AddTo((error), FROM_HERE, brillo::errors::dbus::kDomain, \
                       (code), (message))

#define DEBUGD_ADD_ERROR_FMT(error, code, format, ...)                      \
  brillo::Error::AddToPrintf((error), FROM_HERE,                            \
                             brillo::errors::dbus::kDomain, (code), format, \
                             ##__VA_ARGS__)

#define DEBUGD_ADD_PERROR(error, code, message)                               \
  brillo::Error::AddToPrintf((error), FROM_HERE,                              \
                             brillo::errors::dbus::kDomain, (code), "%s: %s", \
                             (message), base::safe_strerror(errno).c_str())

#endif  // DEBUGD_SRC_ERROR_UTILS_H_
